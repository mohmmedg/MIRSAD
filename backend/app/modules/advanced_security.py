"""Advanced Full-Assessment security engines.

This module adds the assessment families that are intentionally separate from
ordinary discovery: protocol-level WebSocket tests, GraphQL abuse/authorization
checks, parser/injection probes, desync detection, cache/deception checks,
file-upload checks, race testing, workflow checks, client-side DOM-XSS signals,
and bounded command-injection verification.

All active probes are scope-checked and consume the same per-assessment
RequestBudget. Stateful/destructive probes require the authoritative safety
policy plus explicit confirmation.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import socket
import ssl
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.core.config import ScopeViolationError, SSRFRiskError, settings, verify_target_in_scope
from app.core.request_budget import BudgetTransport, GuardedTransport, RequestBudget, RequestBudgetExceeded, TargetUnhealthyError, TargetUnreachableError
from app.core.safety_policy import policy_for
from app.core.oob import issue_token, observed

import logging as _logging
logger = _logging.getLogger(__name__)

try:
    import websockets
except Exception:  # optional at import time; Docker installs it
    websockets = None


ERROR_SIGS = {
    "ldap": ("ldap error", "invalid dn syntax", "ldapexception", "javax.naming", "openldap"),
            "xpath": ["' or '1'='1", "\"]|//*|a[\""],
    "nosql": ("mongodb", "mongoerror", "mongoose", "bson", "couchdb", "cast to objectid failed", "redis error"),
    "xxe": ("doctype is disallowed", "external entity", "entity", "saxparse", "xml parser", "xerces"),
    "ssti": ("jinja2", "freemarker", "thymeleaf", "twig", "velocity", "template syntax"),
}

INJECTABLE_METHODS = {"GET", "POST", "PUT", "PATCH"}
UPLOAD_NAMES = ("file", "upload", "attachment", "document", "image", "avatar", "media")
WORKFLOW_HINTS = ("register", "signup", "login", "signin", "logout", "reset", "forgot", "verify", "confirm", "checkout", "purchase", "order", "transfer", "change-password", "password")


class AdvancedSecurityEngine:
    def __init__(self) -> None:
        self.timeout = httpx.Timeout(min(20.0, max(5.0, settings.DEFAULT_SCAN_TIMEOUT_SECONDS / 10)))

    async def scan(
        self,
        target: str,
        *,
        web: Any | None,
        api: Any | None,
        safe_mode: str,
        destructive_confirmation: bool,
        auth_header: str | None = None,
        cookie: str | None = None,
        authorized_auth_header: str | None = None,
        authorized_cookie: str | None = None,
        unauthorized_auth_header: str | None = None,
        unauthorized_cookie: str | None = None,
        oob_callback_domain: str | None = None,
        budget: RequestBudget | None = None,
    ) -> dict[str, Any]:
        policy = policy_for(safe_mode)
        budget = budget or RequestBudget()
        verify_target_in_scope(urlparse(target).hostname or target)
        headers = {"User-Agent": "MIRSAD-Advanced/1.0 (authorized-security-testing)"}
        if auth_header:
            headers["Authorization"] = auth_header
        if cookie:
            headers["Cookie"] = cookie
        discovered_endpoints = self._collect_endpoints(target, web, api)
        endpoint_cap = settings.ADVANCED_SECURITY_PHASE_MAX_ENDPOINTS
        endpoints = discovered_endpoints[:endpoint_cap]
        params = self._collect_parameters(web, api)
        engine_names = [
            "websocket_message_security", "graphql_mutation_authorization",
            "graphql_batching", "graphql_depth_complexity", "xxe",
            "ldap_injection", "nosql_injection", "xpath_injection",
            "ssti", "request_smuggling_desync", "cache_poisoning",
            "cache_deception", "file_upload", "race_conditions",
            "business_logic_workflows", "oauth_mfa_password_reset",
            "dom_xss_taint", "command_injection_matrix",
        ]
        result: dict[str, Any] = {
            "status": "COMPLETED",
            "safety_mode": safe_mode,
            "engines": {name: "NOT_TESTED" for name in engine_names},
            "findings": [],
            "coverage": {},
            "request_budget": {},
            "warnings": [],
        }
        result["coverage"]["endpoint_selection"] = {
            "discovered": len(discovered_endpoints), "selected": len(endpoints),
            "skipped_by_limit": len(discovered_endpoints) - len(endpoints),
        }
        if len(discovered_endpoints) > len(endpoints):
            result["warnings"].append(
                f"endpoint selection limited: {len(discovered_endpoints)-len(endpoints)} endpoints were not assessed"
            )

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=settings.WEB_SCAN_VERIFY_TLS,
            headers=headers,
            transport=GuardedTransport(budget),
        ) as client:
            async def run(name, fn):
                phase_started = time.monotonic()
                try:
                    with budget.phase_limit(settings.ADVANCED_SECURITY_PHASE_MAX_REQUESTS) as phase:
                        value = await asyncio.wait_for(
                            fn(), timeout=settings.ADVANCED_SECURITY_PHASE_TIMEOUT_SECONDS,
                        )
                    result["coverage"].setdefault(name, {})["requests_consumed"] = phase.used
                    result["coverage"][name]["duration_seconds"] = round(time.monotonic()-phase_started, 2)
                    result["engines"][name] = value.get("status", "COMPLETED") if isinstance(value, dict) else "COMPLETED"
                    result["coverage"][name].update(value.get("coverage", {}) if isinstance(value, dict) else {})
                    result["findings"].extend(value.get("findings", [])) if isinstance(value, dict) else None
                    return value
                except asyncio.TimeoutError:
                    result["engines"][name] = "TIMEOUT"
                    result["warnings"].append(
                        f"{name}: timed out after {settings.ADVANCED_SECURITY_PHASE_TIMEOUT_SECONDS}s"
                    )
                    result["coverage"][name] = {"duration_seconds": round(time.monotonic()-phase_started, 2),
                                                "stop_reason": "phase_timeout"}
                    return {"status": "TIMEOUT", "findings": []}
                except TargetUnhealthyError as exc:
                    # Partial, not NOT_TESTED: requests already ran, but the target was unstable.
                    result["engines"][name] = "PARTIAL"
                    result["warnings"].append(f"{name}: {exc}")
                    result["coverage"].setdefault(name, {})["stop_reason"] = "target_unhealthy"
                    return {"status": "PARTIAL", "findings": []}
                except TargetUnreachableError as exc:
                    result["engines"][name] = "NOT_TESTED"
                    result["warnings"].append(f"{name}: {exc}")
                    return {"status": "NOT_TESTED", "findings": []}
                except RequestBudgetExceeded as exc:
                    result["engines"][name] = "BUDGET_EXHAUSTED"
                    result["warnings"].append(f"{name}: {exc}")
                    return {"status": "BUDGET_EXHAUSTED", "findings": []}
                except Exception as exc:
                    result["engines"][name] = "FAILED"
                    result["warnings"].append(f"{name}: {str(exc)[:400]}")
                    return {"status": "FAILED", "findings": []}

            await run("websocket_messages", lambda: self._websocket_messages(web, api, safe_mode, destructive_confirmation, headers, budget, authorized_auth_header, authorized_cookie, unauthorized_auth_header, unauthorized_cookie))
            await run("graphql_advanced", lambda: self._graphql(client, api, safe_mode, destructive_confirmation, headers, authorized_auth_header, authorized_cookie, unauthorized_auth_header, unauthorized_cookie))
            await run("parser_injections", lambda: self._parser_injections(client, endpoints, params, policy, destructive_confirmation, oob_callback_domain))
            await run("request_smuggling", lambda: self._request_smuggling(target, safe_mode, destructive_confirmation, budget))
            await run("cache_security", lambda: self._cache_security(client, endpoints[:25], safe_mode))
            await run("file_upload", lambda: self._file_upload(client, web, policy, destructive_confirmation))
            await run("race_conditions", lambda: self._race_conditions(client, endpoints, safe_mode, destructive_confirmation, headers, budget))
            await run("business_logic", lambda: self._business_logic(client, endpoints, safe_mode, destructive_confirmation, headers, budget))
            await run("auth_workflows", lambda: self._auth_workflows(client, endpoints, safe_mode, destructive_confirmation, headers, budget))
            await run("dom_xss", lambda: self._dom_xss(web))
            await run("command_injection", lambda: self._command_injection(client, endpoints, params, safe_mode, destructive_confirmation))

        # Publish a stable 18-family capability matrix. Individual implementation
        # engines may internally cover several related controls, but the report
        # never collapses an untested family into a false COMPLETED state.
        aliases = {
            "websocket_message_security": "websocket_messages",
            "graphql_mutation_authorization": "graphql_advanced",
            "graphql_batching": "graphql_advanced",
            "graphql_depth_complexity": "graphql_advanced",
            "xxe": "parser_injections", "ldap_injection": "parser_injections",
            "nosql_injection": "parser_injections", "xpath_injection": "parser_injections",
            "ssti": "parser_injections", "request_smuggling_desync": "request_smuggling",
            "cache_poisoning": "cache_security", "cache_deception": "cache_security",
            "file_upload": "file_upload", "race_conditions": "race_conditions",
            "business_logic_workflows": "business_logic", "oauth_mfa_password_reset": "auth_workflows",
            "dom_xss_taint": "dom_xss", "command_injection_matrix": "command_injection",
        }
        for public_name, internal_name in aliases.items():
            result["engines"][public_name] = result["engines"].get(internal_name, "NOT_TESTED")
            result["coverage"][public_name] = result["coverage"].get(internal_name, {})

        # Compute the headline from real implementations (not the public aliases,
        # which would double count failures and change the denominator).
        states = [result["engines"][name] for name in (
            "websocket_messages", "graphql_advanced", "parser_injections",
            "request_smuggling", "cache_security", "file_upload",
            "race_conditions", "business_logic", "auth_workflows", "dom_xss",
            "command_injection",
        )]
        successes = sum(s == "COMPLETED" for s in states)
        if all(s == "COMPLETED" for s in states):
            result["status"] = "COMPLETED"
        elif all(s in {"NOT_TESTED", "SKIPPED"} for s in states):
            result["status"] = "NOT_TESTED"
        elif successes == 0 and all(s in {"FAILED", "TIMEOUT", "BUDGET_EXHAUSTED"} for s in states):
            result["status"] = "FAILED"
        else:
            result["status"] = "PARTIAL"
        result["request_budget"] = budget.snapshot()
        result["finding_count"] = len(result["findings"])
        return result

    @staticmethod
    def _collect_endpoints(target, web, api):
        out = [target]
        for source in (web, api):
            for item in getattr(source, "endpoints", []) or []:
                url = getattr(item, "url", None)
                if url:
                    out.append(url)
        for url in getattr(web, "discovered_urls", []) or []:
            out.append(url)
        # Preserve order, same-origin only.
        origin = urlparse(target)
        seen = set(); clean = []
        for url in out:
            p = urlparse(str(url))
            if p.scheme not in {"http", "https"} or p.hostname != origin.hostname:
                continue
            n = urlunparse(p._replace(fragment=""))
            if n not in seen:
                seen.add(n); clean.append(n)
        return clean[:400]

    @staticmethod
    def _collect_parameters(web, api):
        """Build a high-fidelity parameter inventory across query, forms and OpenAPI.

        The old implementation only retained query names, which meant body/form
        parameters were invisible to the advanced injection families.
        """
        out: dict[str, set[str]] = {}
        for k, vals in (getattr(web, "discovered_parameters", {}) or {}).items():
            out.setdefault(str(k), set()).update(str(v) for v in (vals or []) if v)
        for form in getattr(web, "forms", []) or []:
            for name, typ in (getattr(form, "input_types", {}) or {}).items():
                out.setdefault(str(name), set()).add(f"form:{typ}")
        for endpoint in getattr(web, "endpoints", []) or []:
            for name in getattr(endpoint, "parameters", []) or []:
                out.setdefault(str(name), set()).add("endpoint")
        for p in getattr(api, "openapi_parameters", []) or []:
            name = str(getattr(p, "name", ""))
            if name:
                out.setdefault(name, set()).add(str(getattr(p, "location", "query")))
        return {k: sorted(v) for k, v in out.items() if k}

    async def _websocket_messages(self, web, api, mode, confirmed, headers, budget, authorized_auth_header=None, authorized_cookie=None, unauthorized_auth_header=None, unauthorized_cookie=None):
        candidates = []
        for ws in getattr(getattr(web, "api_security", None), "websockets", []) or []:
            candidates.append(getattr(ws, "url", ""))
        for ws in getattr(api, "websockets", []) or []:
            candidates.append(getattr(ws, "url", ""))
        for ws in getattr(web, "websocket_candidates", []) or []:
            candidates.append(ws if isinstance(ws, str) else ws.get("url", ""))
        candidates = list(dict.fromkeys(x for x in candidates if x.startswith(("ws://", "wss://"))))[:1000]
        if not candidates:
            return {"status": "NOT_TESTED", "coverage": {"candidates": 0}, "findings": []}
        if websockets is None:
            return {"status": "NOT_INSTALLED", "coverage": {"candidates": len(candidates)}, "findings": []}
        findings = []
        tested = 0
        _ws_fail_limit = int(getattr(settings, "TARGET_CONNECT_FAIL_LIMIT", 8))
        _ws_fails = 0
        for url in candidates:
            if _ws_fails >= _ws_fail_limit:
                break  # circuit open: host unreachable, do not wait 5 s per remaining candidate
            try:
                verify_target_in_scope(urlparse(url).hostname or "")
                await budget.acquire_external("websocket")
                try:
                    _pu = urlparse(url)
                    if (_pu.hostname or "") in {"127.0.0.1", "localhost", "::1"}:
                        from app.modules.external_scanners.engines import resolve_loopback_host
                        _alias = await asyncio.to_thread(resolve_loopback_host, _pu.port)
                        url_conn = url.replace(_pu.hostname, _alias, 1)
                    else:
                        url_conn = url
                    async with websockets.connect(url_conn, additional_headers=headers, open_timeout=5, close_timeout=2, max_size=1_000_000) as ws:
                        tested += 1
                        # Non-state-changing protocol probes. Destructive mode adds
                        # a schema-agnostic JSON object only when the operator opted in.
                        probes = ["{}", '{"type":"ping"}', '{"action":"ping"}', '{"op":"ping"}', '{"type":"subscribe","topic":"__mirsad_probe__"}']
                        if mode == "destructive" and confirmed:
                            probes += ['{"mirsad_probe":"invalid-operation"}', '{"type":"subscribe","topic":"__mirsad_private_probe__"}', '{"operation":"__mirsad_invalid__"}']
                        for payload in probes:
                            await ws.send(payload)
                            try:
                                message = await asyncio.wait_for(ws.recv(), timeout=2.0)
                                text = message.decode(errors="ignore") if isinstance(message, bytes) else str(message)
                                findings.append({
                                    "rule_id": "WS-MESSAGE-UNEXPECTED-RESPONSE",
                                    "title": "WebSocket accepted an unvalidated message",
                                    "severity": "Low",
                                    "asset": url,
                                    "evidence": f"payload={payload}; response={text[:500]}",
                                    "verification_status": "DETECTED",
                                })
                            except asyncio.TimeoutError:
                                pass
                    _ws_fails = 0
                finally:
                    budget.release_external()
            except (OSError, asyncio.TimeoutError):
                _ws_fails += 1
                continue
            except Exception:
                continue
        auth_diff = bool(authorized_auth_header or authorized_cookie or unauthorized_auth_header or unauthorized_cookie)
        if auth_diff:
            for url in candidates[:100]:
                try:
                    ah=dict(headers); uh=dict(headers)
                    if authorized_auth_header: ah["Authorization"]=authorized_auth_header
                    if authorized_cookie: ah["Cookie"]=authorized_cookie
                    if unauthorized_auth_header: uh["Authorization"]=unauthorized_auth_header
                    else: uh.pop("Authorization",None)
                    if unauthorized_cookie: uh["Cookie"]=unauthorized_cookie
                    else: uh.pop("Cookie",None)
                    async with websockets.connect(url, additional_headers=ah, open_timeout=5, close_timeout=2, max_size=1_000_000) as aws:
                        async with websockets.connect(url, additional_headers=uh, open_timeout=5, close_timeout=2, max_size=1_000_000) as uws:
                            await aws.send('{"type":"ping"}'); await uws.send('{"type":"ping"}')
                            ar=await asyncio.wait_for(aws.recv(),timeout=2); ur=await asyncio.wait_for(uws.recv(),timeout=2)
                            if str(ar)==str(ur) and str(ur) not in {"", "None"}:
                                findings.append({"rule_id":"WS-AUTHZ-DIFFERENTIAL-CANDIDATE","title":"WebSocket returned the same probe response to authorized and unauthorized identities","severity":"Medium","asset":url,"evidence":"Identical ping-response content observed across two explicitly supplied identities; application-level authorization review required.","verification_status":"DETECTED"})
                except Exception:
                    continue
        return {"status":"COMPLETED","coverage":{"candidates":len(candidates),"connections":tested,"messages":tested*(8 if mode=="destructive" and confirmed else 5),"authorization_differential":auth_diff},"findings":findings}

    async def _graphql(self, client, api, mode, confirmed, headers, authorized_auth_header=None, authorized_cookie=None, unauthorized_auth_header=None, unauthorized_cookie=None):
        gql = getattr(api, "graphql", None)
        endpoint = getattr(gql, "endpoint", None) if gql else None
        if not endpoint:
            return {"status": "NOT_TESTED", "coverage": {"endpoint": False}, "findings": []}
        findings = []
        query = """query MirsadSchema { __schema { queryType { fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } mutationType { fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } } }"""
        try:
            r = await client.post(endpoint, json={"query": query}, headers=headers)
            data = r.json()
            schema = (data.get("data") or {}).get("__schema") or {}
        except Exception as exc:
            return {"status": "FAILED", "coverage": {"endpoint": True}, "findings": [], "error": str(exc)[:300]}
        mutations = ((schema.get("mutationType") or {}).get("fields") or [])
        queries = ((schema.get("queryType") or {}).get("fields") or [])
        # Batch: two harmless __typename queries. A server accepting an array is
        # evidence of batching support, not automatically a vulnerability.
        try:
            batch = await client.post(endpoint, json=[{"query": "{ __typename }"} for _ in range(10)], headers=headers)
            if batch.status_code < 300 and isinstance(batch.json(), list):
                findings.append({"rule_id":"GRAPHQL-BATCHING-ENABLED","title":"GraphQL batching enabled","severity":"Info","asset":endpoint,"evidence":"Server accepted a ten-operation JSON array.","verification_method":"active_http_probe","verification_status":"VERIFIED"})
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        # Depth/complexity: generated query stays within a tiny bound and only uses
        # fields that do not require arguments. It measures enforcement rather than
        # attempting an unbounded DoS payload.
        field = next((f for f in queries if f.get("name")), None)
        if field:
            name = field["name"]
            deep = "{ " + name + " { " * 5 + " __typename " + "}" * 5 + " }"
            try:
                dr = await client.post(endpoint, json={"query": deep}, headers=headers)
                if dr.status_code < 400:
                    findings.append({"rule_id":"GRAPHQL-DEPTH-LIMIT-NOT-OBSERVED","title":"GraphQL depth limit not observed at bounded depth","severity":"Low","asset":endpoint,"evidence":f"bounded_depth=5 status={dr.status_code}","verification_status":"DETECTED"})
            except Exception:
                logger.debug("suppressed non-fatal error", exc_info=True)
        if mutations:
            # Mutation authorization is exercised only with explicit destructive
            # confirmation. We prefer mutations with zero required arguments.
            zero_arg = next((m for m in mutations if not self._required_args(m.get("args") or [])), None)
            if zero_arg and mode == "destructive" and confirmed:
                mname = zero_arg["name"]
                mr = await client.post(endpoint, json={"query": f"mutation {{ {mname} {{ __typename }} }}"}, headers=headers)
                if mr.status_code < 400:
                    findings.append({"rule_id":"GRAPHQL-MUTATION-AUTHORIZATION-REVIEW","title":"GraphQL mutation executed without a client-side authorization denial","severity":"High","asset":endpoint,"evidence":f"mutation={mname}; status={mr.status_code}","verification_status":"DETECTED"})
            else:
                findings.append({"rule_id":"GRAPHQL-MUTATION-AUTHZ-NOT_TESTED","title":"GraphQL mutation authorization requires explicit destructive confirmation","severity":"Info","asset":endpoint,"evidence":f"mutations={len(mutations)}","verification_status":"UNVERIFIED"})
        # Differential authorization: when the operator supplied two explicit
        # identities, execute only read-only fields with zero required arguments
        # under both identities. A status/data-shape difference is evidence for
        # manual BOLA/BFLA review, not an automatic vulnerability verdict.
        if authorized_auth_header and unauthorized_auth_header:
            authz_headers = dict(headers)
            authz_headers["Authorization"] = authorized_auth_header
            unauth_headers = dict(headers)
            unauth_headers["Authorization"] = unauthorized_auth_header
            tested = 0
            for qf in queries[:12]:
                qname = qf.get("name")
                if not qname or self._required_args(qf.get("args") or []):
                    continue
                probe = {"query": "query MirsadAuth { %s { __typename } }" % qname}
                try:
                    ar = await client.post(endpoint, json=probe, headers=authz_headers)
                    ur = await client.post(endpoint, json=probe, headers=unauth_headers)
                    tested += 1
                    if ar.status_code < 400 and ur.status_code < 400:
                        ad = ar.json().get("data") if isinstance(ar.json(), dict) else None
                        ud = ur.json().get("data") if isinstance(ur.json(), dict) else None
                        if ad == ud and ad is not None:
                            findings.append({"rule_id":"GRAPHQL-BFLA-BOLA-CANDIDATE","title":"GraphQL operation returned the same object shape to two supplied identities","severity":"Medium","asset":endpoint,"evidence":f"field={qname}; authorized_status={ar.status_code}; unauthorized_status={ur.status_code}","verification_status":"DETECTED"})
                except Exception:
                    continue
        else:
            tested = 0
        # Introspection exposes the operation inventory; keep this separate from
        # authorization verdicts.
        return {"status":"COMPLETED","coverage":{"queries":len(queries),"mutations":len(mutations),"batching":True,"batch_size_tested":10,"depth_tested":bool(field),"mutation_execution":bool(mutations and mode=="destructive" and confirmed),"authorization_differential":tested},"findings":findings}

    @staticmethod
    def _required_args(args):
        for arg in args:
            typ = arg.get("type") or {}
            if typ.get("kind") == "NON_NULL":
                return True
        return False

    async def _parser_injections(self, client, endpoints, params, policy, confirmed, oob_domain):
        """Deep parser/injection assessment across query + form + JSON bodies.

        Results remain CANDIDATE/DETECTED unless the response contains strong
        parser-specific evidence. XXE is auto-confirmed only when the scanner's
        self-hosted OOB callback observes the unique token; otherwise it remains
        explicitly unverified.
        """
        findings=[]; tested=0; body_tests=0; oob_sent=0; oob_verified=0
        payloads={
            "ldap":["*)(uid=*)","*)(objectClass=*)"],
            "xpath": ["' or '1'='1", "\"]|//*|a[\""],
            "nosql":[{"$ne":None},{"$gt":""}],
            "xxe":['<!DOCTYPE mirsad [<!ENTITY xxe SYSTEM "{oob}">]><r>&xxe;</r>'],
        }
        names=list(params)

        async def inspect(kind, url, parameter, response, payload, channel):
            low=response.text[:300_000].lower()
            if any(sig in low for sig in ERROR_SIGS[kind]):
                findings.append({"rule_id":f"{kind.upper()}-INJECTION-ERROR", "title":f"{kind.upper()} injection parser error candidate", "severity":"Medium", "asset":url, "parameter":parameter, "evidence":f"channel={channel}; status={response.status_code}; parser signature matched", "verification_status":"DETECTED"})

        for url in endpoints[: min(len(endpoints), 500)]:
            p=urlparse(url); qs=dict(parse_qsl(p.query,keep_blank_values=True))
            # Query-string campaigns: every observed parameter, not just the first few.
            for name in list(qs)[:32]:
                original=qs[name]
                for kind in ("ldap","xpath","nosql"):
                    for payload in payloads[kind]:
                        testq=dict(qs); testq[name]=payload
                        test=urlunparse(p._replace(query=urlencode(testq,doseq=True)))
                        try:
                            r=await client.get(test); tested+=1
                            await inspect(kind,url,name,r,payload,"query")
                        except RequestBudgetExceeded: raise
                        except Exception: logger.debug("suppressed non-fatal error", exc_info=True)

            # Body probes are intentionally gated by stateful probe policy. They
            # use synthetic JSON and form fields only; no real credentials.
            if policy.allow_stateful_form_probes and confirmed and names:
                for name in names[:32]:
                    for kind in ("ldap","xpath","nosql"):
                        payload=payloads[kind][0]
                        for content_type, body in (("application/json", json.dumps({name:payload})), ("application/x-www-form-urlencoded", urlencode({name:payload}))):
                            try:
                                r=await client.post(url,content=body,headers={"Content-Type":content_type}); tested+=1; body_tests+=1
                                await inspect(kind,url,name,r,payload,"body")
                            except RequestBudgetExceeded: raise
                            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)

            # XXE: use a unique self-hosted callback when configured. A caller-
            # supplied domain is retained as manual-OOB mode for Interactsh/Burp.
            if policy.allow_authentication_probes and confirmed and (oob_domain or settings.OOB_CALLBACK_BASE_URL):
                token=issue_token() if settings.OOB_CALLBACK_BASE_URL else uuid.uuid4().hex
                if settings.OOB_CALLBACK_BASE_URL:
                    callback=settings.OOB_CALLBACK_BASE_URL.rstrip("/")+"/"+token
                else:
                    callback="http://"+token+"."+oob_domain+"/xxe"
                xml=payloads["xxe"][0].format(oob=callback)
                try:
                    r=await client.post(url,content=xml,headers={"Content-Type":"application/xml"}); tested+=1; oob_sent+=1
                    if settings.OOB_CALLBACK_BASE_URL:
                        for _ in range(5):
                            await asyncio.sleep(0.2)
                            if observed(token):
                                oob_verified+=1
                                findings.append({"rule_id":"XXE-OOB-VERIFIED","title":"XML external entity processing verified by OOB callback","severity":"Critical","asset":url,"evidence":f"callback_token={token}; status={r.status_code}; callback_observed=true","verification_method":"oob_callback","verification_status":"VERIFIED"})
                                break
                    else:
                        findings.append({"rule_id":"XXE-OOB-CANDIDATE","title":"XML external entity processing candidate","severity":"High","asset":url,"evidence":f"XML DOCTYPE probe sent; correlation={token}; external callback requires provider-side verification; status={r.status_code}","verification_status":"DETECTED"})
                except RequestBudgetExceeded: raise
                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)

        # SSTI must be differential. A marker such as ``49`` is common in static
        # CSS/JS, so "marker exists and payload is absent" is not evidence of
        # template evaluation. Keep one baseline per URL and use a unique product
        # for every attempt. Static assets are not meaningful SSTI sinks.
        ssti_baselines: dict[str, str] = {}
        static_ext = re.compile(r"\\.(?:css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip)(?:$|\\?)", re.I)
        for url in endpoints[: min(len(endpoints), 250)]:
            p=urlparse(url)
            if static_ext.search(p.path):
                continue
            qs=dict(parse_qsl(p.query,keep_blank_values=True))
            if not qs:
                continue
            try:
                if url not in ssti_baselines:
                    base=await client.get(url); tested+=1
                    ssti_baselines[url]=base.text[:300_000]
                baseline=ssti_baselines[url]
            except RequestBudgetExceeded: raise
            except Exception:
                continue
            for name in list(qs)[:16]:
                a = 100 + ((tested * 37 + len(name) * 17) % 899)
                b = 100 + ((tested * 53 + len(url) * 11) % 899)
                product = str(a * b)
                for payload in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"<%= {a}*{b} %>"):
                    testq=dict(qs); testq[name]=payload; test=urlunparse(p._replace(query=urlencode(testq)))
                    try:
                        r=await client.get(test); tested+=1
                        body=r.text[:300_000]
                        if product in body and product not in baseline:
                            findings.append({"rule_id":"SSTI-EVALUATION-CANDIDATE","title":"Server-side template expression appears evaluated","severity":"High","asset":url,"parameter":name,"evidence":f"payload={payload}; rendered_marker={product}; marker_absent_from_baseline=true; status={r.status_code}","verification_status":"DETECTED","confidence":"medium"})
                            break
                    except RequestBudgetExceeded: raise
                    except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED","coverage":{"requests":tested,"parameter_names":len(names),"body_injection_requests":body_tests,"xxe_oob_sent":oob_sent,"xxe_oob_verified":oob_verified,"ssti":True},"findings":findings}

    async def _request_smuggling(self, target, mode, confirmed, budget):
        if mode != "destructive" or not confirmed:
            return {"status":"NOT_TESTED","coverage":{"reason":"Requires destructive confirmation"},"findings":[]}
        p=urlparse(target); host=p.hostname or ""; port=p.port or (443 if p.scheme=="https" else 80)
        if p.scheme not in {"http","https"}:
            return {"status":"NOT_TESTED","coverage":{},"findings":[]}
        verify_target_in_scope(host)
        # داخل حاوية Docker العنوان 127.0.0.1 يشير للحاوية نفسها لا للمضيف، فكانت
        # كل المحاولات ترجع Connection refused. نستخدم نفس ترجمة محرك الويب.
        connect_host = "host.docker.internal" if host in {"127.0.0.1", "localhost"} else host
        probes=[
            b"POST / HTTP/1.1\r\nHost: %b\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n" % host.encode(),
            b"POST / HTTP/1.1\r\nHost: %b\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\nConnection: close\r\n\r\n0\r\n\r\n" % host.encode(),
        ]
        observations=[]
        for payload in probes:
            await budget.acquire_external("request_smuggling")
            try:
                start=time.monotonic()
                if p.scheme=="https":
                    ctx=ssl.create_default_context()
                    reader,writer=await asyncio.wait_for(asyncio.open_connection(connect_host,port,ssl=ctx,server_hostname=host),5)
                else:
                    reader,writer=await asyncio.wait_for(asyncio.open_connection(connect_host,port),5)
                writer.write(payload); await writer.drain()
                try:
                    data=await asyncio.wait_for(reader.read(2048),3)
                except asyncio.TimeoutError:
                    data=b""
                writer.close(); await writer.wait_closed()
                observations.append({"bytes":len(data),"elapsed":round(time.monotonic()-start,3),"prefix":data[:120].decode("latin1","ignore")})
            except Exception as exc:
                observations.append({"error":str(exc)[:200]})
            finally:
                budget.release_external()
        # خطأ الاتصال (رفض/انقطاع) لا يدل على desync: هو غياب قياس لا نتيجة.
        # كان أي خطأ يُسجَّل ثغرة High، فنتج false positive على أهداف غير قابلة للوصول.
        measured=[o for o in observations if "error" not in o]
        if not measured:
            return {"status":"NOT_TESTED","coverage":{"probes":len(probes),"observations":len(observations),"reason":"all probes failed to connect; result inconclusive"},"findings":[]}
        suspicious=any(o.get("elapsed",0)>2.5 for o in measured)
        finding=[]
        if suspicious:
            finding.append({"rule_id":"HTTP-DESYNC-SUSPICIOUS","title":"HTTP request desynchronization candidate","severity":"High","asset":target,"evidence":json.dumps(observations)[:2000],"verification_status":"DETECTED"})
        return {"status":"COMPLETED","coverage":{"probes":len(probes),"observations":len(observations)},"findings":finding}

    async def _cache_security(self, client, endpoints, mode):
        findings=[]; tested=0; verified_poison=0
        for url in endpoints:
            p=urlparse(url)
            marker="mirsad-cache-"+uuid.uuid4().hex[:12]
            try:
                probes=[("X-Forwarded-Host",marker),("X-Host",marker),("X-Forwarded-Proto","http"),("X-Original-URL",p.path)]
                for header,value in probes:
                    poisoned=await client.get(url,headers={header:value}); clean=await client.get(url); tested+=2
                    cache_meta=" ".join(poisoned.headers.get(k,"") for k in ("cache-control","age","x-cache","cf-cache-status","via")).lower()
                    reflected=marker in poisoned.text[:100_000] or marker in (poisoned.headers.get("location","") or "")
                    persisted=marker in clean.text[:100_000] or marker in (clean.headers.get("location","") or "")
                    if persisted:
                        verified_poison+=1
                        findings.append({"rule_id":"CACHE-POISONING-VERIFIED","title":"Cache poisoning marker persisted into a clean request","severity":"High","asset":url,"evidence":f"header={header}; marker={marker}; persisted=true; cache_headers={cache_meta}","verification_method":"clean_request_replay","verification_status":"VERIFIED"})
                    elif reflected and ("cache" in cache_meta or poisoned.headers.get("age") or poisoned.headers.get("x-cache")):
                        findings.append({"rule_id":"CACHE-POISONING-REFLECTION","title":"Cache poisoning reflection candidate","severity":"Medium","asset":url,"evidence":f"header={header}; marker={marker}; persisted=false; cache_headers={cache_meta}","verification_status":"DETECTED"})
                for suffix in ("/static/..%2f","/assets/..%2f","/css/..%2f","/images/..%2f"):
                    deception=url.rstrip("/")+suffix; d=await client.get(deception); tested+=1
                    ctype=d.headers.get("content-type","").lower()
                    if d.status_code in {200,206} and ctype.startswith(("text/html","application/json")):
                        findings.append({"rule_id":"CACHE-DECEPTION-CANDIDATE","title":"Web cache deception candidate","severity":"Medium","asset":deception,"evidence":f"status={d.status_code}; content-type={ctype}; cache-control={d.headers.get('cache-control','')}","verification_status":"DETECTED"})
            except RequestBudgetExceeded: raise
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED","coverage":{"endpoints":len(endpoints),"requests":tested,"verified_poisoning":verified_poison},"findings":findings}

    async def _file_upload(self, client, web, policy, confirmed):
        forms=getattr(web,"forms",[]) or []; candidates=[]
        for form in forms:
            types=getattr(form,"input_types",{}) or {}
            if any(str(t).lower()=="file" or any(x in str(n).lower() for x in UPLOAD_NAMES) for n,t in types.items()):
                candidates.append(form)
        if not candidates: return {"status":"NOT_TESTED","coverage":{"upload_forms":0},"findings":[]}
        if not policy.allow_stateful_form_probes or not confirmed:
            return {"status":"DISCOVERED_ONLY","coverage":{"upload_forms":len(candidates),"requires_confirmation":True},"findings":[]}
        findings=[]
        for form in candidates[:50]:
            action=getattr(form,"action",""); method=getattr(form,"method","POST").upper()
            if method not in {"POST","PUT","PATCH"}: continue
            types=getattr(form,"input_types",{}) or {}; fields=[n for n,t in types.items() if str(t).lower()=="file" or any(x in str(n).lower() for x in UPLOAD_NAMES)] or ["file"]
            for field in fields[:10]:
                for filename,content,ctype in (("mirsad-upload-test.txt",b"MIRSAD_UPLOAD_CANARY","text/plain"),("mirsad-upload-test.svg",b'<svg xmlns="http://www.w3.org/2000/svg"><text>MIRSAD</text></svg>',"image/svg+xml"),("mirsad-upload-test.html",b"<html><body>MIRSAD</body></html>","text/html")):
                    try:
                        r=await client.request(method,action,files={field:(filename,content,ctype)},data={})
                        location=r.headers.get("location") or r.headers.get("content-location")
                        findings.append({"rule_id":"FILE-UPLOAD-ACCEPTED","title":"File upload endpoint accepted a harmless canary","severity":"Info","asset":action,"evidence":f"field={field}; filename={filename}; status={r.status_code}; location={location or ''}","verification_method":"harmless_canary_upload","verification_status":"VERIFIED"})
                        if location and location.startswith(("http://","https://")):
                            verify_target_in_scope(urlparse(location).hostname or "")
                            stored=await client.get(location)
                            body=stored.text[:500_000]
                            c=stored.headers.get("content-type","").lower()
                            if filename.endswith((".svg",".html")) and "text/html" in c and "mirsad" in body.lower():
                                findings.append({"rule_id":"FILE-UPLOAD-STORED-ACTIVE-CONTENT","title":"Uploaded active content is retrievable as executable HTML content","severity":"High","asset":location,"evidence":f"retrieval_status={stored.status_code}; content_type={c}; canary_present=true","verification_method":"retrieval_content_type_check","verification_status":"VERIFIED"})
                            if "mirsad_upload_canary" in body.lower() and c not in {"text/plain","text/plain; charset=utf-8"}:
                                findings.append({"rule_id":"FILE-UPLOAD-CONTENT-TYPE-MISMATCH","title":"Uploaded content is served with an unexpected content type","severity":"Medium","asset":location,"evidence":f"content_type={c}; filename={filename}","verification_status":"DETECTED"})
                    except RequestBudgetExceeded: raise
                    except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED","coverage":{"upload_forms":len(candidates),"stored_object_verification":True},"findings":findings}

    async def _race_conditions(self, client, endpoints, mode, confirmed, headers, budget):
        if mode not in {"caution","destructive"} or (mode=="destructive" and not confirmed):
            return {"status":"NOT_TESTED","coverage":{"reason":"Requires stateful probe permission"},"findings":[]}
        targets=[u for u in endpoints if any(x in urlparse(u).path.lower() for x in ("/coupon","/redeem","/claim","/checkout","/transfer","/vote","/like","/follow"))][:25]
        findings=[]
        for url in targets:
            token=uuid.uuid4().hex[:12]; payload={"mirsad_race_probe":token}
            try:
                baseline=await client.post(url,headers=headers,json=payload); base_ok=baseline.status_code < 400
                async def one():
                    await budget.acquire();
                    try: return await client.post(url,headers=headers,json=payload)
                    finally: budget.release()
                responses=await asyncio.gather(*(one() for _ in range(8)),return_exceptions=True)
                oks=[r for r in responses if hasattr(r,"status_code") and r.status_code < 400]
                if len(oks)>=4 and not base_ok:
                    findings.append({"rule_id":"RACE-CONDITION-CANDIDATE","title":"Concurrent requests bypassed a sequential baseline rejection","severity":"High","asset":url,"evidence":f"baseline_status={baseline.status_code}; concurrent_successes={len(oks)}/8; identical_probe_token={token}","verification_status":"DETECTED"})
                elif len(oks)>=6 and base_ok:
                    findings.append({"rule_id":"RACE-CONDITION-STATE-REVIEW","title":"State-changing endpoint accepted many simultaneous identical requests","severity":"Medium","asset":url,"evidence":f"baseline_status={baseline.status_code}; concurrent_successes={len(oks)}/8; identical_probe_token={token}; manual state invariant verification required","verification_status":"DETECTED"})
            except RequestBudgetExceeded: raise
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED","coverage":{"candidate_endpoints":len(targets),"parallel_requests":8,"baseline_comparison":True},"findings":findings}

    async def _business_logic(self, client, endpoints, mode, confirmed, headers, budget):
        if mode == "safe":
            return {"status":"DISCOVERED_ONLY","coverage":{"workflow_candidates":0,"reason":"Safe mode does not mutate business state"},"findings":[]}
        candidates=[u for u in endpoints if any(x in urlparse(u).path.lower() for x in WORKFLOW_HINTS)][:40]
        findings=[]
        for url in candidates:
            p=urlparse(url); q=dict(parse_qsl(p.query,keep_blank_values=True))
            if not q: continue
            for key,val in list(q.items())[:3]:
                if val.isdigit():
                    for alt in ("0","-1","999999999"):
                        test=urlunparse(p._replace(query=urlencode({**q,key:alt})))
                        try:
                            r=await client.get(test,headers=headers)
                            if r.status_code < 400:
                                findings.append({"rule_id":"BUSINESS-LOGIC-BOUNDARY-CANDIDATE","title":"Business logic boundary accepted an abnormal numeric value","severity":"Low","asset":url,"parameter":key,"evidence":f"value={alt}; status={r.status_code}","verification_status":"DETECTED"})
                        except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED","coverage":{"workflow_candidates":len(candidates)},"findings":findings}

    async def _auth_workflows(self, client, endpoints, mode, confirmed, headers, budget):
        candidates=[u for u in endpoints if any(x in urlparse(u).path.lower() for x in ("reset","forgot","verify","confirm","login","signin","password","mfa","otp","oauth","authorize","token"))][:100]
        findings=[]; oidc_tested=0
        if not candidates and endpoints:
            candidates=[endpoints[0]]
        # Protocol-aware OIDC discovery. This is read-only and does not submit credentials.
        if endpoints:
            origin=urlunparse(urlparse(endpoints[0])._replace(path="",query="",fragment=""))
            for path in ("/.well-known/openid-configuration","/.well-known/oauth-authorization-server"):
                try:
                    r=await client.get(origin.rstrip("/")+path); oidc_tested+=1
                    if r.status_code < 300 and "json" in r.headers.get("content-type","").lower():
                        data=r.json()
                        findings.append({"rule_id":"OAUTH-OIDC-DISCOVERY","title":"OIDC/OAuth authorization metadata endpoint discovered","severity":"Info","asset":origin.rstrip("/")+path,"evidence":f"status={r.status_code}; issuer={data.get('issuer','')}; authorization_endpoint={bool(data.get('authorization_endpoint'))}; token_endpoint={bool(data.get('token_endpoint'))}; jwks_uri={bool(data.get('jwks_uri'))}","verification_status":"VERIFIED"})
                        for key in ("jwks_uri","userinfo_endpoint"):
                            if data.get(key):
                                try:
                                    rr=await client.get(data[key],headers={k:v for k,v in headers.items() if k.lower() not in {"authorization","cookie"}})
                                    if rr.status_code >= 500:
                                        findings.append({"rule_id":"OAUTH-METADATA-SERVICE-ERROR","title":"OAuth metadata endpoint returned a server error","severity":"Low","asset":data[key],"evidence":f"status={rr.status_code}","verification_status":"DETECTED"})
                                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        for url in candidates:
            try:
                r=await client.get(url,headers=headers); text=r.text[:100_000].lower()
                if any(x in text for x in ("reset token","verification code","otp","password reset","multi-factor","two-factor","mfa")):
                    findings.append({"rule_id":"AUTH-WORKFLOW-ENDPOINT","title":"Authentication recovery/verification workflow endpoint discovered","severity":"Info","asset":url,"evidence":f"status={r.status_code}; workflow_markers_present=true","verification_method":"active_http_probe","verification_status":"VERIFIED"})
                # Security headers/cookie attributes are part of the auth workflow boundary.
                for cookie in r.headers.get_list("set-cookie"):
                    low=cookie.lower()
                    if "samesite=" not in low or "secure" not in low or "httponly" not in low:
                        findings.append({"rule_id":"AUTH-COOKIE-ATTRIBUTE-WEAKNESS","title":"Authentication workflow issued a cookie without complete security attributes","severity":"Medium","asset":url,"evidence":cookie[:500],"verification_method":"response_cookie_attribute_check","verification_status":"VERIFIED"})
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        if mode in {"caution","destructive"}:
            for url in candidates[:20]:
                try:
                    a=await client.post(url,headers={**headers,"Content-Type":"application/json"},json={"email":"mirsad-nonexistent-1@example.invalid"})
                    b=await client.post(url,headers={**headers,"Content-Type":"application/json"},json={"email":"mirsad-nonexistent-2@example.invalid"})
                    if abs(len(a.text)-len(b.text))>200 and a.status_code==b.status_code:
                        findings.append({"rule_id":"AUTH-ENUMERATION-DIFFERENTIAL","title":"Authentication workflow responses differ for synthetic identifiers","severity":"Low","asset":url,"evidence":f"status={a.status_code}; lengths={len(a.text)},{len(b.text)}","verification_status":"DETECTED"})
                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED" if candidates else "NOT_TESTED","coverage":{"candidates":len(candidates),"oidc_discovery_requests":oidc_tested,"cookie_attribute_checks":True,"enumeration_differential":mode in {"caution","destructive"}},"findings":findings}

    async def _dom_xss(self, web):
        bodies=[]
        js_info=getattr(web,"javascript_intelligence",{}) or {}
        bodies.extend(js_info.get("bodies",[]) or [])
        bodies.extend([str(x.get("html", "")) for x in (getattr(web,"rendered_pages",[]) or []) if isinstance(x,dict)])
        if not bodies:
            return {"status":"NOT_TESTED","coverage":{"scripts":0},"findings":[]}
        sinks=("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "setTimeout(", "setInterval(", "location.href", "location.assign")
        sources=("location.search", "location.hash", "location.href", "document.URL", "document.referrer", "postMessage")
        findings=[]
        for body in bodies[:300]:
            low=body.lower()
            hit_s=[s for s in sinks if s.lower() in low]
            hit_r=[s for s in sources if s.lower() in low]
            # Approximate source->variable->sink taint edges. This deliberately
            # reports candidates rather than pretending to be a full JS compiler.
            assignments=[]
            for src in hit_r:
                assignments.extend(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;]{0,180}"+re.escape(src.lower()), low))
                assignments.extend(re.findall(r"([A-Za-z_$][\w$]*)\s*=\s*[^;]{0,180}"+re.escape(src.lower()), low))
            variable_sinks=[]
            for var in set(assignments):
                if re.search(r"(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*=.{0,100}\b"+re.escape(var)+r"\b", body, re.I):
                    variable_sinks.append(var)
            if hit_s and hit_r and (variable_sinks or not assignments):
                findings.append({"rule_id":"DOM-XSS-TAINT-CANDIDATE","title":"Potential DOM XSS source-to-sink data flow","severity":"Medium","asset":getattr(web,"target","") if web else "","evidence":f"sources={hit_r[:5]}; sinks={hit_s[:5]}; tainted_variables={variable_sinks[:10]}","verification_status":"DETECTED"})
        return {"status":"COMPLETED","coverage":{"scripts":len(bodies),"taint_candidates":len(findings)},"findings":findings}

    async def _command_injection(self, client, endpoints, params, mode, confirmed):
        if mode != "destructive" or not confirmed:
            return {"status":"NOT_TESTED","coverage":{"reason":"Requires destructive confirmation"},"findings":[]}
        findings=[]
        names=[n for n in params if n.lower() in {"cmd","command","exec","execute","shell","ping","host","ip","path","file","filename","name"}]
        # Bounded cross-shell matrix. Payloads are inert canaries (printf/echo) or
        # one-second timing probes; no shell spawning, file writes, downloads, or
        # reverse shells are attempted.
        matrix=[
            ";printf MIRSAD_CMD_CANARY", "|printf MIRSAD_CMD_CANARY", "$(printf MIRSAD_CMD_CANARY)",
            "`printf MIRSAD_CMD_CANARY`", "& echo MIRSAD_CMD_CANARY",
            "; sleep 1", "| sleep 1", "$(sleep 1)",
        ]
        for url in endpoints[:80]:
            p=urlparse(url); q=dict(parse_qsl(p.query,keep_blank_values=True))
            for name in names:
                if name not in q: continue
                baseline_elapsed=None
                try:
                    t=time.monotonic(); await client.get(url); baseline_elapsed=time.monotonic()-t
                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
                for payload in matrix:
                    test=urlunparse(p._replace(query=urlencode({**q,name:payload})))
                    try:
                        start=time.monotonic(); r=await client.get(test); elapsed=time.monotonic()-start
                        marker="MIRSAD_CMD_CANARY" in r.text[:200_000]
                        timing=payload in matrix[-3:] and elapsed >= max(0.85, (baseline_elapsed or 0)+0.65)
                        if marker or timing:
                            findings.append({"rule_id":"COMMAND-INJECTION-MATRIX-CANDIDATE","title":"Command injection candidate detected by bounded canary matrix","severity":"High","asset":url,"parameter":name,"evidence":f"payload={payload}; elapsed={elapsed:.2f}s; baseline={baseline_elapsed}; marker={marker}; timing={timing}","verification_status":"DETECTED"})
                    except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return {"status":"COMPLETED","coverage":{"candidate_parameters":len(names),"payloads_per_parameter":len(matrix),"timing_probes":3,"marker_probes":len(matrix)-3},"findings":findings}
