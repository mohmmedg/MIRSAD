"""MIRSAD Web Security Engine.

Architecture inspired by ZAP/Nuclei concepts without copying their code:
- bounded same-origin crawling
- endpoint/parameter/form/JS discovery
- passive response analysis
- safe template-driven HTTP checks
- small, non-destructive active canary checks
- structured evidence for the AI analysis layer

The engine intentionally avoids destructive actions, credential attacks,
DoS-style tests, arbitrary request methods, or user-supplied shell commands.
"""

import asyncio
import json
import re
import socket
import ssl
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.core.config import ScopeViolationError, SSRFRiskError, settings, verify_target_in_scope, check_ssrf_risk
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import scan_policy
from app.schemas.network import ScanStatus
from app.modules.api_security.scanner import APISecurityScanner
from app.modules.technology.js_analyzer import analyze_js
from app.schemas.web import (
    FormInfo, HeaderCheck, TemplateFinding, TLSInfo, VulnerabilityCheck,
    WebEndpoint, WebScanResult,
)

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1_500_000
DEFAULT_PAGES = 60
MAX_PAGES = 150
DEFAULT_DEPTH = 3
MAX_DEPTH = 5
MAX_ENDPOINTS = 300
MAX_JS_ASSETS = 80
MAX_PARAMS_PER_URL = 12
REQUEST_CONCURRENCY = 8

SECURITY_HEADERS_TO_CHECK = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]
SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark", "sqlite3.operationalerror",
    "postgresql error", "ora-01756", "microsoft odbc", "pg_query()",
]
XSS_MARKER = "sec_scan_xss_marker_9f3a"

PROFILES = {
    "quick": {"pages": 15, "depth": 1, "templates": True, "active": False},
    "balanced": {"pages": 60, "depth": 3, "templates": True, "active": True},
    "deep": {"pages": 120, "depth": 4, "templates": True, "active": True},
    "maximum": {"pages": 150, "depth": 5, "templates": True, "active": True},
    "passive": {"pages": 100, "depth": 4, "templates": True, "active": False},
}


class WebScanEngine:
    def __init__(self) -> None:
        self.timeout = httpx.Timeout(settings.DEFAULT_SCAN_TIMEOUT_SECONDS)
        self.semaphore = asyncio.Semaphore(REQUEST_CONCURRENCY)
        self.template_dir = Path(__file__).resolve().parent / "templates"
        self.api_scanner = APISecurityScanner()

    async def scan(self, target_url: str, profile: str = "balanced", max_pages: int | None = None, max_depth: int | None = None, auth_header: str | None = None, cookie: str | None = None) -> WebScanResult:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"URL غير صالح: '{target_url}'")
        verify_target_in_scope(parsed.hostname)
        if profile not in PROFILES:
            raise ValueError(f"profile غير معروف: {profile}. القيم: {list(PROFILES)}")
        profile_cfg = PROFILES[profile]
        pages = min(max_pages or profile_cfg["pages"], MAX_PAGES)
        depth_limit = min(max_depth or profile_cfg["depth"], MAX_DEPTH)

        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=settings.WEB_SCAN_VERIFY_TLS,
                headers={"User-Agent": "MIRSAD-Scanner/1.0 (authorized-security-testing)", **({"Authorization": auth_header} if auth_header else {}), **({"Cookie": cookie} if cookie else {})},
            ) as client:
                connection_url = self._docker_host_url(target_url)
                response = await self._get_with_redirects(client, connection_url)
                final_url = str(response.url)
                final_parsed = urlparse(final_url)
                origin = (final_parsed.scheme, final_parsed.hostname, final_parsed.port or (443 if final_parsed.scheme == "https" else 80))

                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                tls_info = self._check_tls(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 443)) if parsed.scheme == "https" else None
                security_headers = self._check_security_headers(headers_lower)
                cookie_checks = self._check_cookies(response.headers.get_list("set-cookie"))
                cors_findings = self._check_cors(headers_lower)
                passive_findings = self._passive_response_checks(response, headers_lower)

                robots_urls, sitemap_urls = await self._discover_robots_and_sitemap(client, final_url)
                crawl = await self._crawl(client, final_url, origin, pages, depth_limit)

                urls = list(dict.fromkeys([final_url, *crawl["urls"], *robots_urls, *sitemap_urls]))[:MAX_ENDPOINTS]
                endpoints = crawl["endpoints"]
                forms = crawl["forms"]
                js_assets = crawl["javascript_assets"]
                params = crawl["parameters"]
                api_candidates = self._find_api_candidates(urls, js_assets, crawl["bodies"])

                # Safe template checks: GET/HEAD/OPTIONS only, same-origin.
                template_findings = []
                template_checks_count = 0
                if profile_cfg["templates"]:
                    template_findings, template_checks_count = await self._run_templates(client, final_url, urls, origin)

                vuln_checks: list[VulnerabilityCheck] = []
                if profile_cfg["active"]:
                    # Bounded, non-destructive canaries against discovered query params.
                    for u, names in list(params.items())[:80]:
                        for name in names[:MAX_PARAMS_PER_URL]:
                            vuln_checks.append(await self._test_reflected_xss(client, u, name))
                            vuln_checks.append(await self._test_sqli_error_based(client, u, name))

                # Automatic Web -> API handoff. Every API-looking endpoint discovered
                # by the crawler is fed into the API engine; OpenAPI/GraphQL discovery
                # then enriches the same scan without requiring a second manual scan.
                api_result = None
                api_integration = {
                    "enabled": True,
                    "seed_urls": len(api_candidates),
                    "crawler_endpoints_sent": len(endpoints),
                    "mode": "automatic_web_to_api",
                }
                if profile in {"balanced", "deep", "maximum", "passive"} and endpoints:
                    api_result = await self.api_scanner.scan(
                        target_url=final_url,
                        enable_graphql_introspection=(profile in {"deep", "maximum"}),
                        probe_write_methods=False,
                        auth_header=auth_header,
                        cookie=cookie,
                        discovered_urls=urls[:MAX_ENDPOINTS],
                        discovered_api_candidates=api_candidates[:MAX_ENDPOINTS],
                        max_endpoints=int(scan_policy(tenant_context.get() or "legacy")["max_endpoints"]),
                    )
                    api_integration.update({
                        "api_scan_id": api_result.scan_id,
                        "api_status": api_result.status,
                        "api_endpoints": len(api_result.endpoints),
                        "openapi_discovered": api_result.openapi.discovered,
                        "graphql_discovered": api_result.graphql.discovered,
                    })

                finished_at = datetime.now(timezone.utc)
                return WebScanResult(
                    scan_id=scan_id, target=target_url, status=ScanStatus.COMPLETED,
                    started_at=started_at, finished_at=finished_at,
                    duration_seconds=(finished_at - started_at).total_seconds(), profile=profile,
                    status_code=response.status_code, final_url=final_url,
                    content_type=headers_lower.get("content-type"),
                    server_header=headers_lower.get("server"), tls_info=tls_info,
                    security_headers=security_headers, vulnerability_checks=vuln_checks,
                    discovered_urls=urls, endpoints=endpoints[:MAX_ENDPOINTS], forms=forms,
                    javascript_assets=js_assets[:MAX_JS_ASSETS], discovered_parameters=params,
                    api_candidates=api_candidates, robots_urls=robots_urls, sitemap_urls=sitemap_urls,
                    template_findings=template_findings,
                    crawled_urls_count=len(crawl["urls"]), forms_count=len(forms),
                    endpoints_count=len(endpoints), parameters_count=sum(len(v) for v in params.values()),
                    js_assets_count=len(js_assets), template_checks_count=template_checks_count,
                    template_matches_count=sum(1 for x in template_findings if x.matched),
                    cookie_checks=cookie_checks, cors_findings=cors_findings,
                    passive_findings=passive_findings, scan_warnings=crawl["warnings"],
                    api_security=api_result, api_integration=api_integration, javascript_intelligence=analyze_js(js_assets, crawl["bodies"]),
                )
        except httpx.HTTPError as exc:
            return self._failed(scan_id, target_url, started_at, f"فشل الاتصال بالهدف: {exc}", profile)
        except (ScopeViolationError, SSRFRiskError) as exc:
            return self._failed(scan_id, target_url, started_at, f"تم إيقاف الفحص: {exc}", profile)

    @staticmethod
    def _failed(scan_id, target, started, message, profile):
        finished = datetime.now(timezone.utc)
        return WebScanResult(scan_id=scan_id, target=target, status=ScanStatus.FAILED,
            started_at=started, finished_at=finished,
            duration_seconds=(finished-started).total_seconds(), error_message=message, profile=profile)

    @staticmethod
    def _docker_host_url(url: str) -> str:
        p = urlparse(url)
        if p.hostname in {"127.0.0.1", "localhost"}:
            netloc = "host.docker.internal" + (f":{p.port}" if p.port else "")
            return urlunparse(p._replace(netloc=netloc))
        return url

    async def _get_with_redirects(self, client, url: str, method="GET"):
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            async with self.semaphore:
                response = await client.request(method, current)
            if not response.has_redirect_location:
                return response
            nxt = urljoin(current, response.headers["location"])
            host = urlparse(nxt).hostname
            if not host:
                break
            verify_target_in_scope(host)
            current = self._docker_host_url(nxt)
        return response

    async def _crawl(self, client, start_url, origin, max_pages, max_depth):
        queue = deque([(start_url, 0)])
        seen, discovered, endpoints = set(), [], []
        forms, js_assets, bodies, warnings = [], [], [], []
        parameters: dict[str, list[str]] = {}
        while queue and len(discovered) < max_pages:
            current, depth = queue.popleft()
            normalized = self._normalize_url(current)
            if normalized in seen or depth > max_depth:
                continue
            seen.add(normalized)
            p = urlparse(current)
            if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) != origin:
                continue
            try:
                response = await self._get_with_redirects(client, self._docker_host_url(current))
            except Exception as exc:
                warnings.append(f"crawl failed for {current}: {exc}")
                continue
            final = str(response.url)
            fp = urlparse(final)
            if (fp.scheme, fp.hostname, fp.port or (443 if fp.scheme == "https" else 80)) != origin:
                continue
            discovered.append(final)
            qnames = sorted(parse_qs(fp.query).keys())
            if qnames:
                parameters[final] = qnames[:MAX_PARAMS_PER_URL]
            endpoints.append(WebEndpoint(url=final, status_code=response.status_code, content_type=response.headers.get("content-type"), parameters=qnames))
            ctype = response.headers.get("content-type", "").lower()
            body = response.content[:MAX_BODY_BYTES].decode("utf-8", errors="ignore")
            bodies.append(body[:200_000])
            if "javascript" in ctype or fp.path.lower().endswith(".js"):
                js_assets.append(final)
            if "html" not in ctype:
                continue
            links, form_infos, assets = self._extract_html(body, final)
            forms.extend(form_infos)
            for a in assets:
                if a not in js_assets and len(js_assets) < MAX_JS_ASSETS:
                    js_assets.append(a)
            # Extract endpoints from inline/external JS without executing it.
            js_links = self._extract_js_urls(body, final)
            links.extend(js_links)
            for link in links:
                lp = urlparse(link)
                if (lp.scheme, lp.hostname, lp.port or (443 if lp.scheme == "https" else 80)) != origin:
                    continue
                verify_target_in_scope(lp.hostname)
                n = self._normalize_url(link)
                if n not in seen and len(seen) + len(queue) < max_pages * 3:
                    queue.append((link, depth + 1))
        return {"urls": list(dict.fromkeys(discovered)), "endpoints": endpoints,
                "forms": forms[:300], "javascript_assets": list(dict.fromkeys(js_assets)),
                "parameters": parameters, "bodies": bodies, "warnings": warnings,
                "template_checks_count": 0}

    @staticmethod
    def _extract_html(body, base_url):
        attrs = re.findall(r"(?:href|src|action)\s*=\s*['\"]([^'\"]+)['\"]", body, re.I)
        links = []
        assets = []
        for raw in attrs:
            if raw.startswith(("#", "mailto:", "javascript:", "data:", "tel:")):
                continue
            absolute = urljoin(base_url, raw)
            if urlparse(absolute).scheme in {"http", "https"}:
                links.append(absolute)
                if re.search(r"\.js(?:\?|$)", absolute, re.I):
                    assets.append(absolute)
        forms = []
        for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
            attrs_text, inner = m.groups()
            action_m = re.search(r"action\s*=\s*['\"]([^'\"]*)", attrs_text, re.I)
            method_m = re.search(r"method\s*=\s*['\"]([^'\"]*)", attrs_text, re.I)
            action = urljoin(base_url, action_m.group(1) if action_m else base_url)
            method = (method_m.group(1) if method_m else "GET").upper()
            names, types = [], {}
            for inp in re.finditer(r"<(?:input|textarea|select)\b([^>]*)>", inner, re.I):
                text = inp.group(1)
                nm = re.search(r"name\s*=\s*['\"]([^'\"]+)", text, re.I)
                if nm:
                    name = nm.group(1); names.append(name)
                    tm = re.search(r"type\s*=\s*['\"]([^'\"]+)", text, re.I)
                    types[name] = (tm.group(1).lower() if tm else "text")
            forms.append(FormInfo(action=action, method=method, inputs=list(dict.fromkeys(names)), input_types=types))
        return list(dict.fromkeys(links)), forms, list(dict.fromkeys(assets))

    @staticmethod
    def _extract_js_urls(body, base_url):
        candidates = set()
        for raw in re.findall(r"(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest|url|endpoint)\s*\(?\s*['\"]([^'\"]+)['\"]", body, re.I):
            if raw.startswith(("/", "http://", "https://")):
                candidates.add(urljoin(base_url, raw))
        for raw in re.findall(r"['\"](/(?:api|graphql|swagger|openapi|v\d+)[^'\"]*)['\"]", body, re.I):
            candidates.add(urljoin(base_url, raw))
        return list(candidates)[:100]

    async def _discover_robots_and_sitemap(self, client, base_url):
        p = urlparse(base_url)
        root = urlunparse(p._replace(path="/", query="", fragment=""))
        robots_url = urljoin(root, "/robots.txt")
        sitemap_url = urljoin(root, "/sitemap.xml")
        robots, sitemap = [], []
        for url, target in ((robots_url, robots), (sitemap_url, sitemap)):
            try:
                r = await self._get_with_redirects(client, self._docker_host_url(url))
                if r.status_code < 400:
                    text = r.content[:300_000].decode("utf-8", errors="ignore")
                    if url.endswith("robots.txt"):
                        target.extend([urljoin(root, x.strip()) for x in re.findall(r"(?:Allow|Disallow|Sitemap)\s*:\s*([^#\s]+)", text, re.I)])
                    else:
                        target.extend(re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I | re.S))
            except Exception:
                pass
        return list(dict.fromkeys(robots))[:100], list(dict.fromkeys(sitemap))[:100]

    @staticmethod
    def _find_api_candidates(urls, js_assets, bodies):
        out = set()
        for u in urls:
            if re.search(r"/(?:api|graphql|swagger|openapi|v\d+)(?:/|$)", urlparse(u).path, re.I): out.add(u)
        for body in bodies:
            for raw in re.findall(r"['\"]((?:/|https?://)[^'\"]*(?:api|graphql|swagger|openapi|v\d+)[^'\"]*)['\"]", body, re.I):
                out.add(raw)
        return list(out)[:100]

    async def _run_templates(self, client, base_url, urls, origin):
        if client is None:
            return [], 0
        templates = self._load_templates()
        findings = []
        targets = list(dict.fromkeys([base_url, *urls]))[:100]
        checks_count = 0
        for template in templates:
            for url in targets:
                p = urlparse(url)
                if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) != origin:
                    continue
                path = template.get("path", "/")
                check_url = urljoin(base_url, path)
                try:
                    verify_target_in_scope(urlparse(check_url).hostname or "")
                    method = template.get("method", "GET").upper()
                    if method not in {"GET", "HEAD", "OPTIONS"}:
                        continue
                    r = await self._get_with_redirects(client, self._docker_host_url(check_url), method=method)
                    body = r.content[:500_000].decode("utf-8", errors="ignore") if method != "HEAD" else ""
                    matched, evidence = self._match_template(template, r, body)
                    checks_count += 1
                    findings.append(TemplateFinding(template_id=template["id"], name=template["name"], severity_hint=template.get("severity", "Info"), url=check_url, method=method, status_code=r.status_code, evidence=evidence, matched=matched, tags=template.get("tags", [])))
                except Exception:
                    continue
        return [x for x in findings if x.matched], checks_count

    def _load_templates(self):
        templates = []
        if not self.template_dir.exists(): return templates
        for path in sorted(self.template_dir.glob("*.json")):
            try:
                templates.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return templates

    @staticmethod
    def _match_template(template, response, body):
        status = template.get("status")
        if status is not None and response.status_code not in status:
            return False, None
        for name, expected in template.get("headers", {}).items():
            value = response.headers.get(name, "")
            if expected.get("exists") is True and not value: return False, None
            if expected.get("contains") and expected["contains"].lower() not in value.lower(): return False, None
        for pattern in template.get("body_regex", []):
            if re.search(pattern, body, re.I | re.S):
                return True, f"Body matched /{pattern}/"
        if template.get("status") and not template.get("body_regex") and not template.get("headers"):
            return True, f"HTTP status {response.status_code}"
        return False, None

    def _passive_response_checks(self, response, headers_lower):
        findings = []
        if "server" in headers_lower and re.search(r"/\d", headers_lower["server"]): findings.append("Server header exposes a version-like value")
        if "x-powered-by" in headers_lower: findings.append("X-Powered-By header is exposed")
        if headers_lower.get("content-type", "").startswith("text/html") and "content-security-policy" not in headers_lower: findings.append("CSP header absent on HTML response")
        if "cache-control" not in headers_lower and response.request.url.scheme == "https": findings.append("Cache-Control not explicitly set on HTTPS response")
        if "set-cookie" in headers_lower and "secure" not in headers_lower["set-cookie"].lower() and response.request.url.scheme == "https": findings.append("A Set-Cookie response was observed without Secure")
        return findings

    def _check_tls(self, hostname, port):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock, context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert(); protocol = tls_sock.version(); cipher = tls_sock.cipher()
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if cert and cert.get("notAfter") else None
            days = (expires - datetime.now(timezone.utc)).days if expires else None
            issuer = None
            if cert and cert.get("issuer"):
                parts = {str(item[0]): str(item[1]) for rdn in cert["issuer"] for item in [rdn[0]]}
                issuer = parts.get("organizationName") or parts.get("commonName")
            return TLSInfo(enabled=True, protocol_version=protocol, cipher_suite=cipher[0] if cipher else None, certificate_valid=(days is not None and days > 0), certificate_expires_at=expires, days_until_expiry=days, issuer=issuer)
        except ssl.SSLCertVerificationError as exc:
            return TLSInfo(enabled=True, certificate_valid=False, error=f"شهادة غير موثوقة: {exc}")
        except Exception as exc:
            return TLSInfo(enabled=True, error=f"تعذّر فحص TLS: {exc}")

    @staticmethod
    def _check_security_headers(headers):
        return [HeaderCheck(header_name=n, present=headers.get(n.lower()) is not None, value=headers.get(n.lower())) for n in SECURITY_HEADERS_TO_CHECK]

    @staticmethod
    def _check_cookies(cookies):
        out=[]
        for raw in cookies:
            name=raw.split("=",1)[0].strip() or "unknown"; low=raw.lower()
            if "secure" not in low: out.append(f"Cookie '{name}' لا يحتوي Secure")
            if "httponly" not in low: out.append(f"Cookie '{name}' لا يحتوي HttpOnly")
            if "samesite=" not in low: out.append(f"Cookie '{name}' لا يحتوي SameSite")
        return out

    @staticmethod
    def _check_cors(headers):
        value=headers.get("access-control-allow-origin")
        return ["Access-Control-Allow-Origin: *"] if value == "*" else []

    async def _test_reflected_xss(self, client, url, param):
        payload=f'\"><script>{XSS_MARKER}</script>'
        test=self._replace_param(url,param,payload)
        try:
            r=await self._get_with_redirects(client,self._docker_host_url(test)); reflected=f"<script>{XSS_MARKER}</script>" in r.text
            return VulnerabilityCheck(check_name="reflected_xss_canary",tested_parameter=param,payload_used=payload,vulnerable=reflected,evidence="Unescaped canary reflected in response" if reflected else None,url=url,confidence="medium" if reflected else "low")
        except Exception as exc:
            return VulnerabilityCheck(check_name="reflected_xss_canary",tested_parameter=param,payload_used=payload,vulnerable=False,evidence=f"check failed: {exc}",url=url)

    async def _test_sqli_error_based(self, client, url, param):
        payload="'"
        test=self._replace_param(url,param,payload)
        try:
            r=await self._get_with_redirects(client,self._docker_host_url(test)); low=r.text.lower(); sig=next((s for s in SQL_ERROR_SIGNATURES if s in low),None)
            return VulnerabilityCheck(check_name="sqli_error_based",tested_parameter=param,payload_used=payload,vulnerable=bool(sig),evidence=f"Database error signature: {sig}" if sig else None,url=url,confidence="medium" if sig else "low")
        except Exception as exc:
            return VulnerabilityCheck(check_name="sqli_error_based",tested_parameter=param,payload_used=payload,vulnerable=False,evidence=f"check failed: {exc}",url=url)

    @staticmethod
    def _replace_param(url,param,new_value):
        p=urlparse(url); qs=parse_qs(p.query); qs[param]=[new_value]; return urlunparse(p._replace(query=urlencode(qs,doseq=True)))

    @staticmethod
    def _normalize_url(url):
        p=urlparse(url); return urlunparse(p._replace(fragment="",path=p.path or "/"))


WebScanner = WebScanEngine
