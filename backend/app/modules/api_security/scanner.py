"""Integrated API Security engine.

Consumes API endpoints discovered by the Web crawler, then enriches them with
OpenAPI/Swagger metadata, schema checks, GraphQL inventory, method observations,
and safe JWT claims analysis. Secrets are never persisted in results.
"""
import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import SSRFRiskError, ScopeViolationError, settings, verify_target_in_scope, check_ssrf_risk, resolve_safe_target
from app.schemas.api_security import (
    APIEndpoint, APIMethodObservation, APISecurityResult, GraphQLInfo,
    GraphQLOperation, JWTClaimsAnalysis, OpenAPISummary, OpenAPIParameter,
    SchemaValidation, WebSocketEndpoint,
)
from app.modules.api_security.templates.engine import APITemplateEngine
from app.core.request_budget import RequestBudget, BudgetTransport, RequestBudgetExceeded, GuardedTransport
from app.core.safety_policy import policy_for

logger = logging.getLogger(__name__)

COMMON_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json", "/openapi.yaml", "/openapi.yml"]
COMMON_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/api/v1/graphql"]
COMMON_API_PATHS = ["/api", "/api/v1", "/api/v2", "/v1", "/v2"]
# RFC 2606 reserved TLD: guaranteed non-resolvable. Used only as an Origin header value
# to check whether a WebSocket endpoint accepts a handshake regardless of Origin
# (a Cross-Site WebSocket Hijacking indicator). No connection is ever made to it.
WS_ORIGIN_PROBE = "https://mirsad-cswsh-probe.invalid"
MAX_WEBSOCKET_CANDIDATES = 20
INTROSPECTION_QUERY = "query IntrospectionQuery { __schema { queryType { name fields { name args { name type { kind name ofType { kind name } } } } } mutationType { name fields { name args { name type { kind name ofType { kind name } } } } } subscriptionType { name fields { name } } types { name kind fields { name } } } }"
SENSITIVE_GRAPHQL = {"password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "creditcard", "ssn", "privatekey"}
SENSITIVE_JWT = {"password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "apikey"}


class APISecurityScanner:
    def __init__(self) -> None:
        self.timeout = httpx.Timeout(settings.DEFAULT_SCAN_TIMEOUT_SECONDS)
        self.templates = APITemplateEngine(settings.DATA_DIR / "api_templates")

    async def scan(self, target_url: str, spec_url: str | None = None,
                   auth_header: str | None = None, cookie: str | None = None,
                   enable_graphql_introspection: bool = True,
                   probe_write_methods: bool = False,
                   discovered_urls: list[str] | None = None,
                   discovered_api_candidates: list[str] | None = None,
                   discovered_websocket_candidates: list[str] | None = None,
                   max_endpoints: int = 100000, safe_mode: str = "safe", budget: RequestBudget | None = None, local_storage: dict[str, str] | None = None, destructive_confirmation: bool = False,
                   oob_callback_domain: str | None = None) -> APISecurityResult:
        started = datetime.now(timezone.utc); scan_id = str(uuid.uuid4())
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"URL غير صالح: '{target_url}'")
        verify_target_in_scope(parsed.hostname)
        policy = policy_for(safe_mode)
        if safe_mode == "destructive" and not destructive_confirmation:
            raise ValueError("destructive mode requires destructive_confirmation=true")
        probe_write_methods = policy.allow_write_methods
        budget = budget or RequestBudget()
        headers = {"User-Agent": "SecurityScanner-API/2.0 (authorized-security-testing)", "Accept": "application/json, text/html;q=0.8"}
        auth_headers = {}
        if auth_header: auth_headers["Authorization"] = auth_header
        if cookie: auth_headers["Cookie"] = cookie
        if not auth_headers and local_storage:
            token = self._token_from_local_storage(local_storage)
            if token:
                auth_headers["Authorization"] = token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}"
        result = APISecurityResult(scan_id=scan_id, target=target_url, status="running", started_at=started,
                                   auth_mode="bearer_or_authorization" if (auth_header or (auth_headers.get("Authorization"))) else ("cookie" if cookie else "none"),
                                   auth_present=bool(auth_headers))
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=settings.WEB_SCAN_VERIFY_TLS, headers=headers, transport=GuardedTransport(budget)) as client:
                seed_urls = self._sanitize_seeds((discovered_urls or []) + (discovered_api_candidates or []), target_url)
                spec = await self._load_openapi(client, target_url, spec_url, auth_headers, seed_urls)
                result.openapi, endpoints, openapi_data = spec
                if not endpoints:
                    endpoints = await self._discover_api_endpoints(client, target_url, auth_headers, seed_urls)
                endpoints = self._merge_endpoints(endpoints, seed_urls)
                result.endpoints = endpoints[:max(1, min(max_endpoints, 100000))]
                result.openapi_parameters = list(result.openapi.parameters)
                result.graphql = await self._discover_graphql(client, target_url, enable_graphql_introspection, auth_headers, seed_urls)
                result.websockets = await self._discover_websockets(client, discovered_websocket_candidates or [], auth_headers)
                result.jwt_analysis = self._analyze_jwt(auth_header)
                for endpoint in result.endpoints:
                    endpoint.observations = await self._method_matrix(client, endpoint, auth_header, cookie, probe_write_methods, safe_mode, openapi_data, oob_callback_domain)
                    for obs in endpoint.observations:
                        if obs.method in {"POST", "PUT", "PATCH", "DELETE"} and not obs.skipped:
                            result.write_method_observations.append({"method": obs.method, "url": endpoint.url, "status_code": obs.status_code, "note": obs.note, "safe_mode": safe_mode})
                if auth_headers:
                    result.authorization_testing = await self._read_only_bola_candidates(client, result.endpoints, auth_headers)
                if openapi_data:
                    result.openapi.schema_validation = await self._validate_openapi_schemas(client, openapi_data, result.endpoints, auth_headers)
                    result.openapi.schema_validation.extend(self._validate_discovered_request_parameters(openapi_data, result.endpoints))
                result.schema_validations = list(result.openapi.schema_validation)
                result.template_matches = self._evaluate_templates(result.endpoints, result.auth_present)
                result.auth_findings = self._auth_findings(result)
                result.rate_limit_assessment = await self._safe_rate_limit_assessment(client, result.endpoints, auth_headers)
                result.coverage = {
                    "integrated_from_web_crawler": bool(seed_urls),
                    "seed_urls": len(seed_urls),
                    "openapi": result.openapi.discovered,
                    "openapi_endpoints": result.openapi.endpoint_count,
                    "openapi_parameters": len(result.openapi.parameters),
                    "schema_validations": len(result.schema_validations),
                    "api_endpoints": len(result.endpoints),
                    "graphql_discovered": result.graphql.discovered,
                    "graphql_introspection": result.graphql.introspection_attempted,
                    "graphql_operations": len(result.graphql.operations),
                    "templates_loaded": len(self.templates.templates),
                    "methods_observed": sum(len(e.observations) for e in result.endpoints),
                    "write_methods_probed": probe_write_methods,
                    "safety_mode": safe_mode,
                    "write_methods_policy": policy.description,
                    "jwt_claims_analyzed": result.jwt_analysis.present,
                    "websocket_candidates": len(discovered_websocket_candidates or []),
                    "websocket_handshakes_attempted": sum(1 for w in result.websockets if w.handshake_attempted),
                    "websocket_handshakes_accepted": sum(1 for w in result.websockets if w.handshake_accepted),
                    "rate_limit_assessment": result.rate_limit_assessment.get("status", "NOT_TESTED"),
                    "request_budget": budget.snapshot(),
                }
                if not result.auth_present:
                    result.warnings.append("No authentication material was supplied; protected/unprotected access cannot be fully distinguished.")
                if not probe_write_methods:
                    result.warnings.append("Write methods (POST/PUT/PATCH/DELETE) are not actively executed by default.")
                result.request_budget = budget.snapshot()
                result.status = "completed"
        except (ScopeViolationError, SSRFRiskError) as exc:
            result.status = "failed"; result.error_message = f"تم إيقاف الفحص: {exc}"
        except Exception as exc:
            result.status = "failed"; result.error_message = f"API scan failed: {exc}"
        result.finished_at = datetime.now(timezone.utc); result.duration_seconds = (result.finished_at-started).total_seconds()
        return result

    @staticmethod
    def _token_from_local_storage(local_storage: dict[str, str]) -> str | None:
        preferred = ("access_token", "accessToken", "id_token", "idToken", "jwt", "token", "auth_token")
        for key in preferred:
            value = local_storage.get(key)
            if value:
                return str(value)
        for key, value in local_storage.items():
            low = str(key).lower()
            if any(hint in low for hint in ("token", "jwt", "access")) and value:
                try:
                    obj = json.loads(value)
                    if isinstance(obj, dict):
                        for nested in preferred:
                            if obj.get(nested):
                                return str(obj[nested])
                except Exception:
                    logger.debug("suppressed non-fatal error", exc_info=True)
                return str(value)
        return None

    @staticmethod
    def _sanitize_seeds(urls, target_url: str) -> list[str]:
        """Normalize protocol-relative URLs and drop out-of-scope/third-party seeds.

        A single seed such as "//api.ipinfodb.com/..." (found in the target's JS) used to raise
        "invalid HTTP redirect target" and abort the entire API scan, leaving 0 endpoints tested.
        """
        scheme = urlparse(target_url).scheme or "http"
        out: list[str] = []
        for u in urls:
            u = str(u)
            if u.startswith("//"):
                u = f"{scheme}:{u}"
            p = urlparse(u)
            if p.scheme not in {"http", "https"} or not p.hostname:
                continue
            try:
                verify_target_in_scope(p.hostname)
            except Exception:
                continue
            out.append(u)
        return list(dict.fromkeys(out))

    async def _request_safe(self, client, method: str, url: str, **kwargs):
        current = url
        for _ in range(6):
            parsed = urlparse(current)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("invalid HTTP redirect target")
            verify_target_in_scope(parsed.hostname)
            resolve_safe_target(parsed.hostname)
            response = await client.request(method, current, **kwargs)
            if not response.has_redirect_location:
                return response
            current = urljoin(current, response.headers["location"])
        raise ValueError("too many redirects")

    async def _load_openapi(self, client, target, spec_url, auth_headers, seed_urls):
        urls = [spec_url] if spec_url else []
        base = target if target.endswith("/") else target + "/"
        candidates = seed_urls + [urljoin(base, p.lstrip("/")) for p in COMMON_SPEC_PATHS]
        urls += [u for u in candidates if any(x in u.lower() for x in ("openapi", "swagger"))]
        for url in list(dict.fromkeys(urls)):
            try:
                p=urlparse(url); verify_target_in_scope(p.hostname or "")
                r=await self._request_safe(client, "GET", url, headers=auth_headers)
                if r.status_code >= 400: continue
                data=self._parse_spec(r)
                if not isinstance(data, dict) or not (data.get("openapi") or data.get("swagger")): continue
                version=str(data.get("openapi") or data.get("swagger")); info=OpenAPISummary(discovered=True, source_url=str(r.url), version=version, title=(data.get("info") or {}).get("title"))
                info.server_urls=[str(x.get("url")) for x in data.get("servers",[]) if isinstance(x,dict) and x.get("url")]
                schemes=(data.get("components") or {}).get("securitySchemes",{}) if isinstance(data.get("components"),dict) else {}
                info.security_schemes=list(schemes.keys()) if isinstance(schemes,dict) else []; info.global_security=bool(data.get("security"))
                endpoints=[]
                for path,item in (data.get("paths") or {}).items():
                    if not isinstance(item,dict) or not str(path).startswith("/"): continue
                    methods=[m.upper() for m in item if m.lower() in {"get","post","put","patch","delete","head","options","trace"}]
                    server=info.server_urls[0] if info.server_urls else base.rstrip("/")
                    url=(urljoin(base, server.lstrip("/").rstrip("/")+path) if server.startswith("/") else urljoin(server.rstrip("/")+"/",path.lstrip("/")))
                    security=[]; params=[]
                    common_params=item.get("parameters") if isinstance(item.get("parameters"),list) else []
                    for method in methods:
                        op=item.get(method.lower(),{})
                        if not isinstance(op,dict): continue
                        for req in op.get("security") or []:
                            if isinstance(req,dict): security.extend(req.keys())
                        pdefs=common_params+(op.get("parameters") if isinstance(op.get("parameters"),list) else [])
                        for prm in pdefs:
                            if isinstance(prm,dict) and prm.get("name"):
                                sch=prm.get("schema") or {}; params.append(OpenAPIParameter(name=str(prm["name"]),location=str(prm.get("in","unknown")),required=bool(prm.get("required")),schema_type=sch.get("type") if isinstance(sch,dict) else None,format=sch.get("format") if isinstance(sch,dict) else None,example_present=any(k in prm for k in ("example","examples"))))
                    endpoints.append(APIEndpoint(path=path,url=url,methods=list(dict.fromkeys(methods)),source="openapi",security=list(dict.fromkeys(security))))
                    info.parameters.extend(params)
                info.parameters=info.parameters[:1000]; info.endpoint_count=len(endpoints)
                return info,endpoints,data
            except (httpx.HTTPError, ValueError, json.JSONDecodeError): continue
        return OpenAPISummary(), [], None

    @staticmethod
    def _parse_spec(response):
        text=response.text
        if "json" in response.headers.get("content-type","").lower() or text.lstrip().startswith("{"): return response.json()
        try:
            import yaml; return yaml.safe_load(text)
        except Exception as exc:
            logger.warning("API specification parsing failed: %s", type(exc).__name__)
            raise ValueError("API specification could not be parsed") from exc

    async def _discover_api_endpoints(self, client,target,auth_headers,seed_urls):
        candidates=list(dict.fromkeys(seed_urls + [urljoin(target if target.endswith('/') else target+'/', p.lstrip('/')) for p in COMMON_API_PATHS]))
        out=[]
        for url in candidates:
            try:
                p=urlparse(url); verify_target_in_scope(p.hostname or "")
                r=await self._request_safe(client, "GET", url,headers=auth_headers)
                if r.status_code < 500 and (self._looks_api_url(url) or "json" in r.headers.get("content-type","").lower()):
                    out.append(APIEndpoint(path=p.path or '/',url=str(r.url),methods=["GET"],source="web-crawler" if url in seed_urls else "common-path"))
            except (httpx.HTTPError, ValueError, ScopeViolationError, SSRFRiskError):
                logger.debug("API endpoint probe request failed for %s", url, exc_info=True)
        return out

    @staticmethod
    def _looks_api_url(url):
        x=urlparse(url).path.lower(); return "/api" in x or "/graphql" in x or x.startswith("/v1") or x.startswith("/v2")

    @staticmethod
    def _merge_endpoints(endpoints, seed_urls):
        out=[]; seen=set()
        for e in endpoints:
            key=e.url.split('?',1)[0]
            if key not in seen: seen.add(key); out.append(e)
        for u in seed_urls:
            p=urlparse(u)
            if not p.hostname or not APISecurityScanner._looks_api_url(u): continue
            key=u.split('?',1)[0]
            if key not in seen: seen.add(key); out.append(APIEndpoint(path=p.path or '/',url=u,methods=["GET"],source="web-crawler"))
        return out

    async def _discover_graphql(self, client,target,enabled,headers,seed_urls):
        info=GraphQLInfo(introspection_enabled=enabled); candidates=list(dict.fromkeys([u for u in seed_urls if "/graphql" in u.lower()] + [urljoin(target if target.endswith('/') else target+'/',p.lstrip('/')) for p in COMMON_GRAPHQL_PATHS]))
        for url in candidates:
            try:
                r=await self._request_safe(client, "GET", url,headers=headers)
                ctype=r.headers.get("content-type","")
                if r.status_code in {200,400,405} and ("json" in ctype or "graphql" in r.text.lower() or "query" in r.text.lower()): info.discovered=True; info.endpoint=str(r.url); break
            except httpx.HTTPError: continue
        if not info.discovered or not enabled: return info
        info.introspection_attempted=True
        try:
            r=await self._request_safe(client, "POST", info.endpoint,json={"query":INTROSPECTION_QUERY},headers=headers); info.introspection_status=r.status_code; data=r.json(); schema=(data.get("data") or {}).get("__schema") or {}
            if schema:
                info.query_type=(schema.get("queryType") or {}).get("name"); info.mutation_type=(schema.get("mutationType") or {}).get("name"); info.subscription_type=(schema.get("subscriptionType") or {}).get("name")
                types=schema.get("types") or []; info.type_count=len(types); info.field_count=sum(len(t.get("fields") or []) for t in types if isinstance(t,dict))
                for key,label in (("queryType","query"),("mutationType","mutation"),("subscriptionType","subscription")):
                    t=schema.get(key) or {}
                    if t.get("name"):
                        info.operations.append(GraphQLOperation(operation_type=label,type_name=t["name"],fields=[str(f.get("name")) for f in t.get("fields") or [] if isinstance(f,dict)][:500]))
                for t in types:
                    for f in (t.get("fields") or []) if isinstance(t,dict) else []:
                        n=str(f.get("name","")); low=n.lower()
                        if any(x in low for x in SENSITIVE_GRAPHQL): info.sensitive_field_hints.append(f"{t.get('name')}.{n}")
                info.sensitive_field_hints=list(dict.fromkeys(info.sensitive_field_hints))[:100]
            elif data.get("errors"): info.introspection_error=str(data["errors"][:3])[:1000]
        except (httpx.HTTPError,ValueError) as exc: info.introspection_error=str(exc)[:1000]
        return info

    @staticmethod
    def _ws_to_http_url(candidate: str) -> str | None:
        if candidate.startswith("ws://"):
            return "http://" + candidate[len("ws://"):]
        if candidate.startswith("wss://"):
            return "https://" + candidate[len("wss://"):]
        if candidate.startswith(("http://", "https://")):
            return candidate
        return None

    async def _discover_websockets(self, client, candidates: list[str], headers: dict) -> list[WebSocketEndpoint]:
        """Safely verify candidate WebSocket endpoints extracted from crawled HTML/JS.

        Only real, extracted candidates are probed — no well-known paths are guessed,
        since (unlike REST/GraphQL) there is no reliable convention for WebSocket paths.
        The probe is a single HTTP-level Upgrade handshake; no data is ever exchanged
        over an established WebSocket channel, and write/attack payloads are never sent.
        """
        results: list[WebSocketEndpoint] = []
        seen: set[str] = set()
        for raw in list(dict.fromkeys(candidates))[:MAX_WEBSOCKET_CANDIDATES]:
            http_url = self._ws_to_http_url(raw)
            if not http_url:
                continue
            key = http_url.split("?", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            try:
                verify_target_in_scope(urlparse(http_url).hostname or "")
            except (ScopeViolationError, SSRFRiskError):
                continue
            ws = WebSocketEndpoint(url=raw, source="js-discovery")
            probe_headers = {
                **headers,
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
            }
            try:
                ws.handshake_attempted = True
                # A 101 handshake response is outside normal HTTP semantics and some
                # HTTP client internals handle it differently across servers; any
                # unexpected failure here must stay scoped to this one candidate and
                # never fail the whole API scan, so exceptions are recorded as an
                # inconclusive result rather than propagated.
                r = await client.get(http_url, headers=probe_headers, timeout=httpx.Timeout(5.0))
                ws.handshake_status = r.status_code
                ws.handshake_accepted = r.status_code == 101 or "upgrade" in r.headers.get("connection", "").lower()
            except Exception as exc:
                ws.error = str(exc)[:300]
            if ws.handshake_accepted:
                try:
                    origin_headers = {**probe_headers, "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(), "Origin": WS_ORIGIN_PROBE}
                    ws.origin_test_attempted = True
                    r2 = await client.get(http_url, headers=origin_headers, timeout=httpx.Timeout(5.0))
                    ws.origin_test_status = r2.status_code
                    ws.origin_reflected = r2.status_code == 101 or "upgrade" in r2.headers.get("connection", "").lower()
                except Exception:
                    # Origin check is best-effort; a failure here does not affect the discovery finding.
                    logger.debug("WebSocket origin-reflection probe failed for %s", http_url, exc_info=True)
            results.append(ws)
        return results

    async def _safe_rate_limit_assessment(self, client, endpoints, headers):
        """Low-volume adaptive rate-limit signal.

        Uses a small burst followed by a short recovery sample. It never tries
        to overwhelm the target; a 429/Retry-After is strong evidence, while
        a stable 2xx/4xx sequence remains inconclusive.
        """
        candidate = next((e for e in endpoints if "GET" in {m.upper() for m in (e.methods or [])}), None)
        if not candidate:
            return {"status": "NOT_TESTED", "reason": "No GET endpoint available"}
        samples = []
        try:
            import time
            for _ in range(5):
                t = time.monotonic(); r = await self._request_safe(client, "GET", candidate.url, headers=headers)
                samples.append({"status_code": r.status_code, "elapsed_ms": round((time.monotonic()-t)*1000,1), "retry_after": r.headers.get("retry-after")})
            throttled = any(x["status_code"] == 429 for x in samples)
            retry_after = next((x["retry_after"] for x in samples if x["retry_after"]), None)
            return {"status": "THROTTLED" if throttled else "NO_LIMIT_SIGNAL", "endpoint": candidate.url,
                    "requests": len(samples), "samples": samples,
                    "retry_after_observed": retry_after, "confidence": "medium" if throttled else "low",
                    "note": "Absence of throttling is inconclusive; meaningful resource-consumption testing requires endpoint-specific limits and larger operator-approved budgets."}
        except RequestBudgetExceeded as exc:
            return {"status":"BUDGET_EXHAUSTED","endpoint":candidate.url,"reason":str(exc)}
        except Exception as exc:
            return {"status":"FAILED","endpoint":candidate.url,"reason":str(exc)[:300]}

    async def _method_matrix(self, client, endpoint, auth_header, cookie, probe_write, safe_mode, spec=None, oob_callback_domain=None):
        observations = []
        write_observations = []
        declared = {m.upper() for m in (endpoint.methods or [])}
        methods = ["OPTIONS", "HEAD", "GET"] + [m for m in sorted(declared) if m not in {"OPTIONS", "HEAD", "GET"}]
        op_map = (spec or {}).get("paths", {}).get(endpoint.path, {}) if isinstance(spec, dict) else {}
        for method in methods:
            if method in {"POST", "PUT", "PATCH", "DELETE", "TRACE"} and not probe_write:
                observations.append(APIMethodObservation(method=method, skipped=True, note="Write method skipped by safe policy"))
                continue
            if method == "DELETE" and safe_mode != "destructive":
                observations.append(APIMethodObservation(method=method, skipped=True, note="DELETE requires destructive mode"))
                continue
            body = None
            headers = {"User-Agent":"SecurityScanner-API/2.0"}
            op = op_map.get(method.lower()) if isinstance(op_map, dict) else None
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                body, content_type = self._build_safe_request_body(spec, op)
                if body is not None:
                    if oob_callback_domain and safe_mode in {"caution", "destructive"}:
                        body = self._inject_oob_body_canary(body, oob_callback_domain)
                    headers["Content-Type"] = content_type
                elif safe_mode == "caution":
                    observations.append(APIMethodObservation(method=method, skipped=True, note="Caution mode requires an OpenAPI/schema-backed request body for write probing"))
                    continue
            try:
                r = await self._request_safe(client, method, endpoint.url, headers=headers, json=body if body is not None and headers.get("Content-Type", "").startswith("application/json") else None,
                                             content=None if body is not None and headers.get("Content-Type", "").startswith("application/json") else (body if body is not None else None))
                obs = APIMethodObservation(method=method, status_code=r.status_code, allow_header=r.headers.get("allow"), content_type=r.headers.get("content-type"))
                if method in {"POST","PUT","PATCH","DELETE"}:
                    write_observations.append({"method":method,"url":endpoint.url,"status_code":r.status_code,"body_generated":body is not None,"safety_mode":safe_mode})
                    if safe_mode == "destructive" and isinstance(body, dict) and method != "DELETE":
                        probe_body = dict(body); probe_body["__mirsad_unexpected_property"] = "mirsad-canary"
                        try:
                            extra = await self._request_safe(client, method, endpoint.url, headers=headers, json=probe_body)
                            if extra.status_code < 400:
                                write_observations.append({"method":method,"url":endpoint.url,"status_code":extra.status_code,"mass_assignment_candidate":True,"safety_mode":safe_mode,"note":"Unexpected property accepted; verify whether it is persisted or changes authorization-sensitive state."})
                        except Exception:
                            logger.debug("suppressed non-fatal error", exc_info=True)
                if auth_header or cookie:
                    ah = {"User-Agent":"SecurityScanner-API/2.0"}
                    if auth_header: ah["Authorization"] = auth_header
                    if cookie: ah["Cookie"] = cookie
                    try:
                        ar = await self._request_safe(client, method, endpoint.url, headers={**headers, **ah}, json=body if body is not None and headers.get("Content-Type", "").startswith("application/json") else None,
                                                       content=None if body is not None and headers.get("Content-Type", "").startswith("application/json") else (body if body is not None else None))
                        obs.authenticated_status = ar.status_code
                        if ar.status_code != r.status_code:
                            obs.auth_status_delta = f"unauth={r.status_code}, auth={ar.status_code}"
                    except httpx.HTTPError:
                        logger.debug("Authenticated %s request failed for %s", method, endpoint.url, exc_info=True)
                observations.append(obs)
            except RequestBudgetExceeded:
                observations.append(APIMethodObservation(method=method, note="Request budget exhausted"))
                break
            except httpx.HTTPError as exc:
                observations.append(APIMethodObservation(method=method, note=str(exc)[:300]))
        return observations

    def _inject_oob_body_canary(self, body, callback_domain):
        correlation = __import__("uuid").uuid4().hex[:12]
        payload = f"http://{correlation}.{callback_domain}/"
        def walk(value):
            if isinstance(value, dict):
                for key in list(value):
                    low = str(key).lower()
                    if any(x in low for x in ("url", "uri", "callback", "webhook", "endpoint", "image", "avatar", "source", "link", "fetch")):
                        value[key] = payload
                    else:
                        walk(value[key])
            elif isinstance(value, list):
                for item in value: walk(item)
        walk(body)
        return body

    def _build_safe_request_body(self, spec, operation):
        if not isinstance(operation, dict):
            return None, "application/json"
        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") if isinstance(request_body, dict) else None
        if not isinstance(content, dict) or not content:
            return None, "application/json"
        media = next((k for k in ("application/json", "application/*+json") if k in content), next(iter(content), None))
        if not media:
            return None, "application/json"
        schema = content.get(media, {}).get("schema") if isinstance(content.get(media), dict) else None
        if not schema:
            return None, media
        try:
            value = self._example_from_schema(spec, schema, depth=0)
            return value, media
        except Exception:
            return None, media

    def _example_from_schema(self, spec, schema, depth=0):
        if depth > 4 or not isinstance(schema, dict):
            return "mirsad-test"
        ref = schema.get("$ref")
        if ref:
            schema = self._resolve_schema(spec, schema) or {}
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        if "enum" in schema and schema["enum"]:
            return schema["enum"][0]
        typ = schema.get("type")
        if typ == "object" or "properties" in schema:
            return {name:self._example_from_schema(spec, sub, depth+1) for name, sub in (schema.get("properties") or {}).items() if isinstance(sub, dict)}
        if typ == "array":
            return [self._example_from_schema(spec, schema.get("items") or {}, depth+1)]
        if typ == "integer": return 1
        if typ == "number": return 1.0
        if typ == "boolean": return True
        return "mirsad-test"

    async def _read_only_bola_candidates(self, client, endpoints, auth_headers):
        """Bounded object-ID substitution on GET endpoints only.

        This is a candidate detector, not an authorization verdict: changing an
        identifier and receiving another successful object can be legitimate in
        public APIs. The result is explicitly labeled for verification.
        """
        tested=[]; candidates=[]
        for endpoint in endpoints[:60]:
            if "GET" not in {m.upper() for m in (endpoint.methods or [])}:
                continue
            path = urlparse(endpoint.url).path
            parts = path.split("/")
            numeric_indexes = [i for i,p in enumerate(parts) if p.isdigit()]
            if not numeric_indexes:
                continue
            for idx in numeric_indexes[:2]:
                original = parts[idx]
                alternatives = ["1", "2", "999999"]
                for alt in alternatives:
                    if alt == original: continue
                    candidate_parts = list(parts); candidate_parts[idx] = alt
                    candidate = urlparse(endpoint.url)._replace(path="/".join(candidate_parts)).geturl()
                    try:
                        r = await self._request_safe(client, "GET", candidate, headers=auth_headers)
                        item={"url":candidate,"original":endpoint.url,"status_code":r.status_code,"original_id":original,"substituted_id":alt}
                        tested.append(item)
                        if r.status_code < 400:
                            candidates.append({**item,"status":"BOLA_CANDIDATE","reason":"A different object identifier returned a successful response under the same authenticated identity; compare object ownership and authorization server-side."})
                    except RequestBudgetExceeded:
                        return {"status":"BUDGET_EXHAUSTED","tested":len(tested),"findings":candidates,"observations":tested}
                    except Exception:
                        continue
        return {"status":"COMPLETED" if tested else "NOT_TESTED","tested":len(tested),"findings":candidates,"observations":tested}

    async def _validate_openapi_schemas(self, client, spec, endpoints, auth_headers):
        """Validate only the schema that corresponds to the observed response.

        The previous implementation iterated every documented response (for
        example 200 and 422) and compared each one to the single observed
        response. That produced duplicate false positives when the endpoint
        legitimately returned 401/403 because no scan credentials were supplied.
        """
        validations = []
        paths = spec.get("paths") or {}
        for e in endpoints[:200]:
            item = paths.get(e.path)
            if not isinstance(item, dict):
                continue
            for method in [m.lower() for m in e.methods if m.lower() in item]:
                if method not in {"get", "head"}:
                    continue  # passive validation only; never execute write methods
                observed = next((o for o in e.observations if o.method == method.upper()), None)
                if not observed or not observed.status_code:
                    continue
                op = item.get(method) or {}
                responses = op.get("responses") or {}
                if not isinstance(responses, dict):
                    continue
                code = self._select_response_code(responses, observed.status_code)
                if code is None:
                    # An undocumented status is coverage information, not a
                    # schema mismatch unless a matching schema actually exists.
                    continue
                resp = responses.get(code)
                if not isinstance(resp, dict):
                    continue
                schema = ((resp.get("content") or {}).get("application/json") or {}).get("schema")
                if not schema:
                    continue
                expected = self._resolve_schema(spec, schema)
                if not expected:
                    continue
                try:
                    r = await self._request_safe(client, method.upper(), e.url, headers=auth_headers)
                    if r.status_code != observed.status_code:
                        # Dynamic endpoints can change between observations; do
                        # not manufacture a schema mismatch from that race.
                        continue
                    if "json" not in r.headers.get("content-type", "").lower():
                        validations.append(SchemaValidation(
                            endpoint=e.url, method=method.upper(), direction="response",
                            status_code=r.status_code, valid=None,
                            errors=["Response is not JSON while schema declares application/json"],
                        ))
                        continue
                    obj = r.json()
                    errors = self._validate_value(obj, expected, "$")
                    validations.append(SchemaValidation(
                        endpoint=e.url, method=method.upper(), direction="response",
                        status_code=r.status_code, valid=not errors, errors=errors[:20],
                    ))
                except (httpx.HTTPError, ValueError):
                    continue
        return validations[:500]

    @staticmethod
    def _select_response_code(responses, status_code: int) -> str | None:
        exact = str(status_code)
        if exact in responses:
            return exact
        family = f"{status_code // 100}XX"
        if family in responses:
            return family
        if "default" in responses:
            return "default"
        return None


    def _validate_discovered_request_parameters(self, spec, endpoints):
        """Validate crawler-observed query parameters against OpenAPI declarations.

        This is passive: it never mutates or injects request values. It reports
        mismatches between observed query strings and the declared parameter schema.
        """
        validations=[]; paths=spec.get("paths") or {}
        for e in endpoints[:300]:
            item=paths.get(urlparse(e.url).path)
            if not isinstance(item,dict): continue
            query=dict((k, v[0] if v else "") for k,v in __import__('urllib.parse',fromlist=['parse_qs']).parse_qs(urlparse(e.url).query,keep_blank_values=True).items())
            for method in [m.lower() for m in e.methods if m.lower() in item]:
                op=item.get(method) or {}
                params=(item.get("parameters") or [])+(op.get("parameters") or []) if isinstance(op,dict) else []
                errors=[]
                for prm in params:
                    if not isinstance(prm,dict) or prm.get("in")!="query" or prm.get("name") not in query: continue
                    value=query[prm["name"]]; sch=prm.get("schema") or {}; typ=sch.get("type")
                    if typ=="integer":
                        try: int(value)
                        except ValueError: errors.append(f"query parameter '{prm['name']}' is not a valid integer")
                    elif typ=="number":
                        try: float(value)
                        except ValueError: errors.append(f"query parameter '{prm['name']}' is not a valid number")
                    elif typ=="boolean" and value.lower() not in {"true","false","0","1"}: errors.append(f"query parameter '{prm['name']}' is not a valid boolean")
                    if sch.get("enum") and value not in [str(x) for x in sch["enum"]]: errors.append(f"query parameter '{prm['name']}' is outside the declared enum")
                if errors:
                    validations.append(SchemaValidation(endpoint=e.url,method=method.upper(),direction="request",valid=False,errors=errors[:20]))
                elif query and params:
                    validations.append(SchemaValidation(endpoint=e.url,method=method.upper(),direction="request",valid=True,errors=[]))
        return validations[:500]

    @staticmethod
    def _resolve_schema(spec,schema):
        if not isinstance(schema,dict): return None
        ref=schema.get("$ref")
        if ref and ref.startswith("#/components/schemas/"):
            return (spec.get("components") or {}).get("schemas",{}).get(ref.rsplit('/',1)[-1])
        return schema

    def _validate_value(self,value,schema,path):
        errors=[]
        if not isinstance(schema,dict): return errors
        typ=schema.get("type")
        if typ=="object":
            if not isinstance(value,dict): return [f"{path}: expected object"]
            for req in schema.get("required",[]):
                if req not in value: errors.append(f"{path}: missing required property '{req}'")
            for k,sub in (schema.get("properties") or {}).items():
                if k in value: errors.extend(self._validate_value(value[k],sub,f"{path}.{k}"))
        elif typ=="array":
            if not isinstance(value,list): errors.append(f"{path}: expected array")
            else:
                for i,x in enumerate(value[:20]): errors.extend(self._validate_value(x,schema.get("items") or {},f"{path}[{i}]"))
        elif typ=="string" and not isinstance(value,str): errors.append(f"{path}: expected string")
        elif typ=="integer" and (not isinstance(value,int) or isinstance(value,bool)): errors.append(f"{path}: expected integer")
        elif typ=="number" and (not isinstance(value,(int,float)) or isinstance(value,bool)): errors.append(f"{path}: expected number")
        elif typ=="boolean" and not isinstance(value,bool): errors.append(f"{path}: expected boolean")
        return errors

    @staticmethod
    def _analyze_jwt(auth_header):
        out=JWTClaimsAnalysis()
        if not auth_header or not auth_header.lower().startswith("bearer "): return out
        token=auth_header.split(None,1)[1].strip(); parts=token.split('.')
        if len(parts)!=3: out.warnings.append("Authorization bearer value is not a JWT-shaped token."); return out
        try:
            dec=lambda x: json.loads(base64.urlsafe_b64decode(x+'='*((4-len(x)%4)%4)).decode('utf-8'))
            header=dec(parts[0]); payload=dec(parts[1]); out.present=True; out.token_type="JWT"; out.algorithm=header.get("alg")
            out.issuer_present="iss" in payload; out.audience_present="aud" in payload; out.expiry_present="exp" in payload; out.not_before_present="nbf" in payload
            if "exp" in payload:
                try: out.expiry_status="expired" if float(payload["exp"]) < datetime.now(timezone.utc).timestamp() else "valid_or_future"
                except Exception: out.expiry_status="unparseable"
            for k in payload:
                if str(k).lower() in SENSITIVE_JWT: out.sensitive_claims.append(str(k))
            if str(header.get("alg","" )).upper()=="NONE": out.warnings.append("JWT declares alg=none; verify that the server rejects unsigned tokens.")
            if not out.expiry_present: out.warnings.append("JWT payload has no exp claim.")
            if not out.issuer_present: out.warnings.append("JWT payload has no iss claim.")
        except Exception as exc: out.warnings.append(f"JWT claims could not be decoded safely: {exc}")
        return out

    def _evaluate_templates(self, endpoints, auth_present=False):
        matches=[]
        for e in endpoints:
            for o in e.observations:
                headers={};
                if o.allow_header: headers["allow"]=o.allow_header
                # 4.2: content-type is needed for LLM-endpoint templates that
                # gate on "looks like a JSON API response" (content_type_contains
                # in engine.py) - it was already captured on the observation but
                # never forwarded into the header dict the template engine sees.
                if o.content_type: headers["content-type"]=o.content_type
                matches.extend(self.templates.evaluate(e.url, o.status_code, headers, auth_present, bool(e.security), e.methods))
        seen=set(); out=[]
        for m in matches:
            key=(m.template_id,m.endpoint,m.evidence)
            if key not in seen: seen.add(key); out.append(m)
        return out[:500]

    async def test_authorization(self, *, target_url: str, endpoints: list[str],
                                 authorized_auth_header: str | None = None, authorized_cookie: str | None = None,
                                 unauthorized_auth_header: str | None = None, unauthorized_cookie: str | None = None) -> dict:
        """Safe differential GET test using two explicit operator-supplied identities.
        It reports candidates only; a public 2xx response is not called an authz bug.
        """
        verify_target_in_scope(urlparse(target_url).hostname or target_url)
        base = {"User-Agent": "MIRSAD-Authorization-Test/1.0", "Accept": "application/json, text/html;q=0.8"}
        def auth_headers(auth, cookie):
            h=dict(base)
            if auth: h["Authorization"]=auth
            if cookie: h["Cookie"]=cookie
            return h
        tested=[]; candidates=[]
        urls=list(dict.fromkeys(endpoints))[:100]
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=settings.WEB_SCAN_VERIFY_TLS) as client:
            for url in urls:
                if not url.startswith(("http://", "https://")): url=urljoin(target_url, url)
                try:
                    async with __import__('asyncio').Semaphore(1):
                        ar=await client.get(url, headers=auth_headers(authorized_auth_header, authorized_cookie))
                        ur=await client.get(url, headers=auth_headers(unauthorized_auth_header, unauthorized_cookie))
                    item={"url":url, "authorized_status":ar.status_code, "unauthorized_status":ur.status_code,
                          "unauthorized_body_readable": ur.status_code < 400,
                          "authorized_body_readable": ar.status_code < 400}
                    tested.append(item)
                    if ar.status_code < 400 and ur.status_code < 400:
                        candidates.append({**item, "status":"BYPASS_CANDIDATE", "reason":"Both identities received a successful response; confirm that this endpoint is intended to be protected and compare object/resource authorization."})
                except Exception as exc:
                    tested.append({"url":url,"status":"FAILED","reason":str(exc)[:300]})
        return {"status":"COMPLETED", "tested":len(tested), "findings":candidates, "observations":tested,
                "reason":None if tested else "No eligible endpoints were available"}

    @staticmethod
    def _auth_findings(result):
        findings=[]
        # Missing scan credentials are a coverage limitation, not a vulnerability.
        # The caller records this as a warning so it never becomes a Medium finding.
        if result.openapi.discovered and result.openapi.security_schemes and not result.openapi.global_security:
            unsecured_operations = [e.path for e in result.endpoints if e.source == "openapi" and not e.security]
            if unsecured_operations:
                findings.append(
                    f"OpenAPI defines security schemes but {len(unsecured_operations)} operation(s) have no declared security requirement; review authorization."
                )
        for e in result.endpoints:
            for o in e.observations:
                if o.auth_status_delta: findings.append(f"Authentication status changed for {e.path} {o.method}: {o.auth_status_delta}.")
        findings.extend(result.jwt_analysis.warnings)
        if result.graphql.sensitive_field_hints: findings.append(f"GraphQL schema exposes {len(result.graphql.sensitive_field_hints)} potentially sensitive field names; review authorization at field/resolver level.")
        return list(dict.fromkeys(findings))
