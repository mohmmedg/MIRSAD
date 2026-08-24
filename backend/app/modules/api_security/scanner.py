"""Integrated API Security engine.

Consumes API endpoints discovered by the Web crawler, then enriches them with
OpenAPI/Swagger metadata, schema checks, GraphQL inventory, method observations,
and safe JWT claims analysis. Secrets are never persisted in results.
"""
import base64
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import SSRFRiskError, ScopeViolationError, settings, verify_target_in_scope, check_ssrf_risk
from app.schemas.api_security import (
    APIEndpoint, APIMethodObservation, APISecurityResult, GraphQLInfo,
    GraphQLOperation, JWTClaimsAnalysis, OpenAPISummary, OpenAPIParameter,
    SchemaValidation,
)
from app.modules.api_security.templates.engine import APITemplateEngine

COMMON_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json", "/openapi.yaml", "/openapi.yml"]
COMMON_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/api/v1/graphql"]
COMMON_API_PATHS = ["/api", "/api/v1", "/api/v2", "/v1", "/v2"]
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
                   max_endpoints: int = 300) -> APISecurityResult:
        started = datetime.now(timezone.utc); scan_id = str(uuid.uuid4())
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"URL غير صالح: '{target_url}'")
        verify_target_in_scope(parsed.hostname)
        headers = {"User-Agent": "SecurityScanner-API/2.0 (authorized-security-testing)", "Accept": "application/json, text/html;q=0.8"}
        auth_headers = {}
        if auth_header: auth_headers["Authorization"] = auth_header
        if cookie: auth_headers["Cookie"] = cookie
        result = APISecurityResult(scan_id=scan_id, target=target_url, status="running", started_at=started,
                                   auth_mode="bearer_or_authorization" if auth_header else ("cookie" if cookie else "none"),
                                   auth_present=bool(auth_header or cookie))
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=settings.WEB_SCAN_VERIFY_TLS, headers=headers) as client:
                seed_urls = list(dict.fromkeys((discovered_urls or []) + (discovered_api_candidates or [])))
                spec = await self._load_openapi(client, target_url, spec_url, auth_headers, seed_urls)
                result.openapi, endpoints, openapi_data = spec
                if not endpoints:
                    endpoints = await self._discover_api_endpoints(client, target_url, auth_headers, seed_urls)
                endpoints = self._merge_endpoints(endpoints, seed_urls)
                result.endpoints = endpoints[:max(1, min(max_endpoints, 300))]
                result.openapi_parameters = list(result.openapi.parameters)
                result.graphql = await self._discover_graphql(client, target_url, enable_graphql_introspection, auth_headers, seed_urls)
                result.jwt_analysis = self._analyze_jwt(auth_header)
                for endpoint in result.endpoints:
                    endpoint.observations = await self._method_matrix(client, endpoint, auth_header, cookie, probe_write_methods)
                if openapi_data:
                    result.openapi.schema_validation = await self._validate_openapi_schemas(client, openapi_data, result.endpoints, auth_headers)
                    result.openapi.schema_validation.extend(self._validate_discovered_request_parameters(openapi_data, result.endpoints))
                result.schema_validations = list(result.openapi.schema_validation)
                result.template_matches = self._evaluate_templates(result.endpoints, result.auth_present)
                result.auth_findings = self._auth_findings(result)
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
                    "jwt_claims_analyzed": result.jwt_analysis.present,
                }
                if not result.auth_present:
                    result.warnings.append("No authentication material was supplied; protected/unprotected access cannot be fully distinguished.")
                if not probe_write_methods:
                    result.warnings.append("Write methods (POST/PUT/PATCH/DELETE) are not actively executed by default.")
                result.status = "completed"
        except (ScopeViolationError, SSRFRiskError) as exc:
            result.status = "failed"; result.error_message = f"تم إيقاف الفحص: {exc}"
        except Exception as exc:
            result.status = "failed"; result.error_message = f"API scan failed: {exc}"
        result.finished_at = datetime.now(timezone.utc); result.duration_seconds = (result.finished_at-started).total_seconds()
        return result

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
        except Exception: return None

    async def _discover_api_endpoints(self, client,target,auth_headers,seed_urls):
        candidates=list(dict.fromkeys(seed_urls + [urljoin(target if target.endswith('/') else target+'/', p.lstrip('/')) for p in COMMON_API_PATHS]))
        out=[]
        for url in candidates[:300]:
            try:
                p=urlparse(url); verify_target_in_scope(p.hostname or "")
                r=await self._request_safe(client, "GET", url,headers=auth_headers)
                if r.status_code < 500 and (self._looks_api_url(url) or "json" in r.headers.get("content-type","").lower()):
                    out.append(APIEndpoint(path=p.path or '/',url=str(r.url),methods=["GET"],source="web-crawler" if url in seed_urls else "common-path"))
            except httpx.HTTPError: pass
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

    async def _method_matrix(self,client,endpoint,auth_header,cookie,probe_write):
        observations=[]; declared=set(endpoint.methods); methods=["OPTIONS","HEAD","GET"]+[m for m in sorted(declared) if m not in {"OPTIONS","HEAD","GET"} and (probe_write or m=="TRACE")]
        for method in methods:
            if method in {"POST","PUT","PATCH","DELETE"} and not probe_write: observations.append(APIMethodObservation(method=method,skipped=True,note="Write method skipped by safe default")); continue
            try:
                r=await self._request_safe(client, method, endpoint.url); obs=APIMethodObservation(method=method,status_code=r.status_code,allow_header=r.headers.get("allow"),content_type=r.headers.get("content-type"))
                if auth_header or cookie:
                    ah={"User-Agent":"SecurityScanner-API/2.0"};
                    if auth_header: ah["Authorization"]=auth_header
                    if cookie: ah["Cookie"]=cookie
                    try:
                        ar=await self._request_safe(client, method, endpoint.url,headers=ah); obs.authenticated_status=ar.status_code
                        if ar.status_code!=r.status_code: obs.auth_status_delta=f"unauth={r.status_code}, auth={ar.status_code}"
                    except httpx.HTTPError: pass
                observations.append(obs)
            except httpx.HTTPError as exc: observations.append(APIMethodObservation(method=method,note=str(exc)[:300]))
        return observations

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
                matches.extend(self.templates.evaluate(e.url, o.status_code, headers, auth_present, bool(e.security), e.methods))
        seen=set(); out=[]
        for m in matches:
            key=(m.template_id,m.endpoint,m.evidence)
            if key not in seen: seen.add(key); out.append(m)
        return out[:500]

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
        return list(dict.fromkeys(findings))[:100]
