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
import logging
import warnings
import json
import random
import re
import socket
import ssl
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.core.config import ScopeViolationError, SSRFRiskError, settings, verify_target_in_scope, check_ssrf_risk, resolve_safe_target
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import scan_policy
from app.schemas.network import ScanStatus
from app.modules.api_security.scanner import APISecurityScanner
from app.modules.technology.js_analyzer import analyze_js
from app.modules.web_scan.auth_protection import analyze_auth_protection
from app.modules.source_intelligence.engine import analyze_web_source
from app.modules.external_scanners.engines import run_nuclei, run_zap, run_sqlmap, run_ffuf, run_testssl
from app.core.request_budget import RequestBudget, BudgetTransport, RequestBudgetExceeded
from app.core.safety_policy import policy_for
from app.core.scan_health import web_terminal_status
from app.schemas.web import (
    FormInfo, HeaderCheck, LoginResult, TemplateFinding, TLSInfo, VulnerabilityCheck,
    WebEndpoint, WebScanResult,
)

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1_500_000
DEFAULT_PAGES = 60
MAX_PAGES = 500
DEFAULT_DEPTH = 3
MAX_DEPTH = 8
MAX_ENDPOINTS = 100000
MAX_JS_ASSETS = 200
MAX_PARAMS_PER_URL = 12
MAX_FORMS_TESTED = 30
MAX_FIELDS_PER_FORM = 12
# Field types we never inject payloads into — submitting them changes page
# behaviour/navigation rather than testing input handling, or the field is
# already server/hidden state that must be preserved verbatim to keep the
# submission itself valid.
NON_INJECTABLE_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "hidden"}
REQUEST_CONCURRENCY = 8
# Consecutive 429/403 responses (across ALL requests this client makes —
# crawl, templates, and payload checks alike) before the active-testing loop
# stops sending further canaries. See the `_circuit` closure in scan().
WEB_SCAN_CIRCUIT_BREAKER_THRESHOLD = 6

SECURITY_HEADERS_TO_CHECK = [
    "Content-Security-Policy", "Strict-Transport-Security", "Referrer-Policy",
    "Permissions-Policy", "X-Content-Type-Options", "X-Frame-Options",
    "Cache-Control", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]
SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark", "sqlite3.operationalerror",
    "postgresql error", "ora-01756", "microsoft odbc", "pg_query()",
]
# Content of well-known Linux/Windows files, used purely as a detection
# signature — the canary requests the file itself (via a classic traversal
# payload), it never writes or modifies anything, and a match only proves
# the response body contains that file's contents.
LFI_SIGNATURES = [
    ("../../../../../../etc/passwd", "root:x:0:0:"),
    ("../../../../../../etc/passwd%00", "root:x:0:0:"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
]
# Parameter names that commonly load a server-side file/template/include —
# this is the same "content=" style parameter pattern known to be an LFI
# vector on the target scanned in this project.
LFI_PARAM_HINTS = ("file", "page", "path", "include", "template", "content", "doc", "view", "load")
XSS_MARKER = "sec_scan_xss_marker_9f3a"
# Only ever tested against parameter *names* matching these hints — never guessed
# or brute-forced across arbitrary parameters.
REDIRECT_PARAM_HINTS = ("redirect", "return", "returnurl", "return_to", "next", "continue",
                         "callback", "dest", "destination", "target", "redirect_uri", "redirect_url", "out", "forward")
# RFC 2606 reserved TLD: guaranteed non-resolvable. The canary never actually reaches
# this host — only the Location header of a single, non-followed response is inspected.
OPEN_REDIRECT_PROBE = "https://mirsad-redirect-probe.invalid/"
# Parameter names that commonly cause the *server itself* to fetch a
# remote resource server-side (SSRF-prone) — broader than
# REDIRECT_PARAM_HINTS, which is about redirecting the *browser*.
SSRF_PARAM_HINTS = ("url", "uri", "path", "dest", "webhook", "callback", "target", "src", "source",
                    "feed", "link", "fetch", "proxy", "image", "avatar", "endpoint", "host", "site")
COMMAND_PARAM_HINTS = ("cmd", "command", "exec", "execute", "shell", "ping", "host", "ip", "query", "search", "file")

DEFAULT_FORCED_DISCOVERY_PATHS = [
    "/admin", "/administrator", "/login", "/signin", "/dashboard", "/portal",
    "/api", "/api/v1", "/api/docs", "/docs", "/redoc", "/swagger",
    "/swagger-ui", "/openapi.json", "/graphql", "/health", "/healthz",
    "/ready", "/metrics", "/debug", "/actuator", "/actuator/health",
    "/server-status", "/server-info", "/.well-known/security.txt", "/.git/HEAD",
    "/.env", "/robots.txt", "/sitemap.xml", "/backup", "/backups",
    "/uploads", "/files", "/static", "/assets", "/wp-admin", "/phpinfo.php",
]


def _load_forced_discovery_paths() -> list[str]:
    """Prefer the full ffuf quick-tier wordlist (211 curated paths) so this
    read-only GET-based check and ffuf don't maintain two diverging, mostly
    duplicate path lists. Falls back to the small built-in list above if the
    wordlist file isn't present (e.g. running outside the container image).
    """
    wl_path = Path(getattr(settings, "FFUF_WORDLIST_QUICK_PATH", "/app/wordlists/mirsad-ffuf-wordlist-quick.txt"))
    try:
        lines = [ln.strip() for ln in wl_path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
        if lines:
            return [ln if ln.startswith("/") else f"/{ln}" for ln in lines]
    except Exception:
        # `logger` is defined further down this module; use the logger directly so a missing
        # wordlist (running outside the container image) falls back instead of raising NameError at import.
        logging.getLogger(__name__).debug("suppressed non-fatal error", exc_info=True)
    return DEFAULT_FORCED_DISCOVERY_PATHS


FORCED_DISCOVERY_PATHS = _load_forced_discovery_paths()

PROFILES = {
    "quick": {"pages": 15, "depth": 1, "templates": True, "active": False},
    "balanced": {"pages": 60, "depth": 3, "templates": True, "active": True},
    "deep": {"pages": 120, "depth": 4, "templates": True, "active": True},
    "maximum": {"pages": 500, "depth": 8, "templates": True, "active": True},
    "passive": {"pages": 100, "depth": 4, "templates": True, "active": False},
}


logger = logging.getLogger(__name__)


class WebScanEngine:
    def __init__(self) -> None:
        self.timeout = httpx.Timeout(settings.DEFAULT_SCAN_TIMEOUT_SECONDS)
        self.semaphore = asyncio.Semaphore(REQUEST_CONCURRENCY)
        self.template_dir = Path(__file__).resolve().parent / "templates"
        self.api_scanner = APISecurityScanner()

    async def scan(self, target_url: str, profile: str = "balanced", max_pages: int | None = None, max_depth: int | None = None, auth_header: str | None = None, cookie: str | None = None,
                    login_url: str | None = None, login_username: str | None = None, login_password: str | None = None, oob_callback_domain: str | None = None,
                    probe_write_methods: bool = False, safe_mode: str = "safe", budget: RequestBudget | None = None,
                    destructive_confirmation: bool = False, run_external: bool = False) -> WebScanResult:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"URL غير صالح: '{target_url}'")
        verify_target_in_scope(parsed.hostname)
        if profile not in PROFILES:
            raise ValueError(f"profile غير معروف: {profile}. القيم: {list(PROFILES)}")
        profile_cfg = PROFILES[profile]
        policy = policy_for(safe_mode)
        probe_write_methods = policy.allow_write_methods
        pages = min(max_pages or profile_cfg["pages"], MAX_PAGES)
        depth_limit = min(max_depth if max_depth is not None else profile_cfg["depth"], MAX_DEPTH)
        budget = budget or RequestBudget()

        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        # Circuit breaker: the scanner used to have no memory across requests
        # of "this target is rate-limiting/blocking us" — a target returning
        # 429/403 on the very first request still got the full crawl + every
        # XSS/SQLi/LFI/open-redirect/OOB/form/default-credential payload for
        # every discovered parameter, which is both pointless (every one of
        # those requests fails the same way) and looks like abusive traffic
        # to the target. `_circuit` is shared (via closure) between every
        # request this client makes and the active-testing loop below, so a
        # sustained run of blocking responses stops further payload testing
        # early instead of grinding through the full parameter list regardless.
        _circuit = {"consecutive_blocks": 0, "tripped": False, "reason": None}

        async def _track_blocking_response(response: httpx.Response) -> None:
            if response.status_code in (429, 403):
                _circuit["consecutive_blocks"] += 1
                if not _circuit["tripped"] and _circuit["consecutive_blocks"] >= WEB_SCAN_CIRCUIT_BREAKER_THRESHOLD:
                    _circuit["tripped"] = True
                    _circuit["reason"] = (
                        f"Stopped further active payload testing after {_circuit['consecutive_blocks']} consecutive "
                        f"HTTP {response.status_code} responses from the target — it appears to be rate-limiting or "
                        "blocking the scanner. Crawl/discovery results above this point remain valid; XSS/SQLi/LFI/"
                        "open-redirect/OOB/form/default-credential checks were skipped for the remaining parameters "
                        "and forms rather than sent uselessly against a target that is already refusing requests."
                    )
            else:
                _circuit["consecutive_blocks"] = 0

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=settings.WEB_SCAN_VERIFY_TLS,
                transport=BudgetTransport(budget),
                headers={"User-Agent": "MIRSAD-Scanner/1.0 (authorized-security-testing)", **({"Authorization": auth_header} if auth_header else {}), **({"Cookie": cookie} if cookie else {})},
                event_hooks={"response": [_track_blocking_response]},
            ) as client:
                login_result = None
                if login_url and login_username and login_password:
                    login_result = await self._perform_login(client, login_url, login_username, login_password, budget=budget)
                connection_url = self._docker_host_url(target_url)
                response = await self._get_with_redirects(client, connection_url, prefer_get=True)
                final_url = str(response.url)
                final_parsed = urlparse(final_url)
                origin = (final_parsed.scheme, final_parsed.hostname, final_parsed.port or (443 if final_parsed.scheme == "https" else 80))

                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                protection_warnings = []
                body_probe = response.content[:100000].decode("utf-8", errors="ignore").lower()
                protection_markers = ("vercel security", "security challenge", "bot challenge", "captcha", "cf-chl-", "challenge-platform")
                if response.status_code in (401, 403, 429) or any(marker in body_probe for marker in protection_markers):
                    protection_warnings.append(
                        f"Automated web coverage may be limited by an application/WAF protection challenge (HTTP {response.status_code}). "
                        "The scanner does not bypass the protection; authenticated/operator-assisted testing may be required."
                    )
                # 2026-09-19 fix: كانت هذه استدعاءً متزامناً مباشراً (socket +
                # ssl.wrap_socket حاجزَين) داخل scan() غير المتزامنة. مع 4
                # إصدارات TLS × مهلة 6 ثوانٍ لكل منها + فحص شهادة بمهلة 10
                # ثوانٍ، كان بإمكان هذا السطر وحده تجميد event loop للعملية
                # بأكملها — كل طلب لكل مستخدم، بما فيها /health و/auth/me —
                # حتى ~34 ثانية متواصلة أثناء أي فحص HTTPS. هذا هو ما ظهر في
                # DevTools كأخطاء 500 وCORS على /auth/me وتأخر /jobs/{id}
                # لثوانٍ طويلة رغم أنها مجرد قراءة ذاكرة. asyncio.to_thread
                # ينقل الحظر إلى خيط عامل فيبقى الخادم مستجيباً لبقية الطلبات.
                tls_info = (
                    await asyncio.to_thread(self._check_tls, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 443))
                    if parsed.scheme == "https" else None
                )
                security_headers = self._check_security_headers(headers_lower)
                cookie_checks = self._check_cookies(response.headers.get_list("set-cookie"))
                cors_findings = self._check_cors(headers_lower)
                cors_verification = await self._verify_cors(client, final_url, headers_lower)
                if cors_verification.get("status") == "VERIFIED_RISK":
                    cors_findings.append("Verified browser-readable cross-origin exposure with credentials or sensitive response")
                passive_findings = self._passive_response_checks(response, headers_lower)

                robots_urls, sitemap_urls = await self._discover_robots_and_sitemap(client, final_url)
                crawl = await self._crawl(client, final_url, origin, pages, depth_limit, seed_urls=[*robots_urls, *sitemap_urls])
                crawl.setdefault("warnings", []).extend(protection_warnings)

                # SPA rendering pass: a plain HTTP crawl reads server-sent HTML
                # only. Modern Angular/React/Vue apps ship an almost-empty
                # index.html and build the real DOM, links, forms, and API
                # calls client-side after JS runs — a regex crawler is blind to
                # all of that. This is a bounded, additive pass with a real
                # headless browser on just the root page; if Playwright/its
                # browser isn't installed it silently no-ops rather than
                # failing the whole scan (browser_rendering.enabled reflects
                # whether it actually ran, surfaced in scan_warnings below).
                # Carry over whatever session the earlier login step established:
                # cookies from the httpx client's jar (covers both the plain-HTTP
                # form login and the cookie side of a browser-based login), plus
                # the raw localStorage snapshot for apps that keep their token
                # there instead (see _perform_login_via_browser).
                session_cookies = [{"name": n, "value": v, "url": self._docker_host_url(final_url)} for n, v in client.cookies.items()]
                auth_protection = {}
                browser_render = None if not settings.ENABLE_PLAYWRIGHT else await self._render_with_browser(
                    self._docker_host_url(final_url),
                    cookies=session_cookies or None,
                    local_storage=login_result.local_storage if login_result else None,
                    max_pages=pages, max_depth=depth_limit, safe_mode=safe_mode, budget=budget,
                )
                if browser_render:
                    for rendered in browser_render.get("pages", []):
                        page_url = rendered.get("url") or final_url
                        rendered_links, rendered_forms, rendered_assets = self._extract_html(rendered.get("html", ""), page_url)
                        for f in rendered_forms:
                            if f not in crawl["forms"]:
                                crawl["forms"].append(f)
                        for asset in rendered_assets:
                            if asset not in crawl["javascript_assets"] and len(crawl["javascript_assets"]) < MAX_JS_ASSETS:
                                crawl["javascript_assets"].append(asset)
                        crawl["bodies"].append((rendered.get("html") or "")[:200_000])
                        for link in rendered_links:
                            lp = urlparse(link)
                            if (lp.scheme, lp.hostname, lp.port or (443 if lp.scheme == "https" else 80)) == origin and link not in crawl["urls"]:
                                crawl["urls"].append(link)
                    auth_protection = analyze_auth_protection(
                        page_urls=crawl.get("urls", []),
                        forms=crawl.get("forms", []),
                        rendered_html=browser_render.get("pages", []),
                        xhr_requests=browser_render.get("xhr_requests", []),
                        responses=browser_render.get("responses", []),
                        origin_url=final_url,
                    )
                    for req in browser_render["xhr_requests"]:
                        rp = urlparse(req["url"])
                        if (rp.scheme, rp.hostname, rp.port or (443 if rp.scheme == "https" else 80)) != origin:
                            continue
                        if req["url"] not in crawl["urls"]:
                            crawl["urls"].append(req["url"])
                        qnames = sorted(parse_qs(rp.query).keys())
                        if qnames:
                            crawl["parameters"].setdefault(req["url"], qnames[:MAX_PARAMS_PER_URL])
                        source = "browser-websocket" if req.get("resource_type") == "websocket" else "browser-xhr"
                        crawl["endpoints"].append(WebEndpoint(url=req["url"], method=req["method"], source=source, parameters=qnames))
                    for resp in browser_render.get("responses", []):
                        rp = urlparse(resp.get("url",""))
                        if (rp.scheme, rp.hostname, rp.port or (443 if rp.scheme == "https" else 80)) == origin:
                            crawl.setdefault("browser_responses", []).append(resp)
                    crawl["browser_pages_rendered"] = browser_render.get("pages_rendered", 0)
                    crawl["browser_websocket_requests"] = browser_render.get("websocket_requests", [])
                    crawl["scan_warnings"] = crawl.get("warnings", [])
                else:
                    crawl.setdefault("warnings", []).append(
                        "Browser-based rendering (SPA support) did not run — Playwright/Chromium may not be installed in this environment; "
                        "client-side-only links, forms, and API calls on JavaScript-rendered pages were not discovered."
                    )

                forced_endpoints, forced_checks = ([], 0)
                if profile_cfg["active"]:
                    forced_endpoints, forced_checks = await self._forced_browsing(client, final_url, origin)
                    for endpoint in forced_endpoints:
                        if endpoint.url not in crawl["urls"]:
                            crawl["urls"].append(endpoint.url)
                        crawl["endpoints"].append(endpoint)

                urls = list(dict.fromkeys([final_url, *crawl["urls"], *robots_urls, *sitemap_urls]))[:MAX_ENDPOINTS]
                endpoints = crawl["endpoints"]
                forms = crawl["forms"]
                js_assets = crawl["javascript_assets"]
                params = crawl["parameters"]
                api_candidates: list[str] = []
                # Fetch actual JavaScript assets before analysis. Previously JS URLs
                # were zipped against HTML response bodies, so endpoint/secret/source-map
                # intelligence was often attached to the wrong asset.
                js_bodies = await self._fetch_js_assets(client, js_assets, origin)
                js_intelligence = analyze_js([x[0] for x in js_bodies], [x[1] for x in js_bodies])

                # Native Source Intelligence is an enrichment layer, not a second
                # scanner. It consumes the exact HTML/JS already collected by the
                # crawl/browser passes and shares the same request budget for bounded
                # source-map fetches. Secrets are fingerprinted/redacted before the
                # result can reach persistence or the AI layer.
                source_intelligence = {}
                if settings.ENABLE_SOURCE_INTELLIGENCE:
                    html_pages = []
                    for u, body in zip(crawl.get("urls", []), crawl.get("bodies", [])):
                        html_pages.append((u, body))
                    for rendered in (browser_render or {}).get("pages", []):
                        if rendered.get("html"):
                            html_pages.append((rendered.get("url") or final_url, rendered["html"]))
                    try:
                        source_intelligence = await analyze_web_source(
                            client=client,
                            base_url=final_url,
                            html_pages=html_pages,
                            js_bodies=js_bodies,
                            headers=headers_lower,
                            budget=budget,
                            run_detectors=True,
                        )
                    except Exception as exc:
                        # analyze_web_source() now catches its own internal errors and
                        # returns a PARTIAL/FAILED result with whatever it gathered (see
                        # source_intelligence/engine.py). Reaching this branch means the
                        # failure happened outside that function entirely (bad arguments,
                        # an import/setup error, etc.), so it is logged with a full
                        # traceback instead of only the exception class name — the class
                        # name alone ("Exception failed: TypeError") was not enough to
                        # diagnose anything from the scan dashboard.
                        logger.exception("Native source intelligence crashed outside analyze_web_source() for %s", final_url)
                        source_intelligence = {
                            "enabled": True, "status": "FAILED", "findings": [],
                            "warnings": [f"Native source intelligence failed before analysis could start: {type(exc).__name__}: {str(exc)[:300]}"],
                            "coverage": {},
                        }
                    # Source-derived endpoints are assets first. Feed them into the
                    # existing API scanner instead of creating duplicate findings.
                    source_endpoints = [
                        str(x) for x in (source_intelligence.get("javascript", {}).get("endpoints", []) or [])
                        if isinstance(x, str)
                    ] + [
                        str(x) for x in (source_intelligence.get("source_maps", {}).get("endpoints", []) or [])
                        if isinstance(x, str)
                    ]
                    for endpoint in source_endpoints[:5000]:
                        if endpoint not in urls:
                            urls.append(endpoint)
                        if endpoint not in api_candidates:
                            api_candidates.append(endpoint)
                    api_candidates = list(dict.fromkeys(api_candidates))[:MAX_ENDPOINTS]
                    js_intelligence["native_source_intelligence"] = {
                        "status": source_intelligence.get("status", "COMPLETED"),
                        "endpoint_count": len(source_endpoints),
                        "secret_candidates": len(source_intelligence.get("javascript", {}).get("secret_candidates", []) or []),
                        "source_maps": len(source_intelligence.get("source_maps", {}).get("maps_analyzed", []) or []),
                    }
                else:
                    source_intelligence = {"enabled": False, "status": "DISABLED", "findings": [], "warnings": [], "coverage": {}}

                api_candidates = self._find_api_candidates(urls, js_assets, crawl["bodies"] + [b for _, b in js_bodies]) + api_candidates
                api_candidates = list(dict.fromkeys(api_candidates))[:MAX_ENDPOINTS]
                websocket_candidates = self._find_websocket_candidates(crawl["bodies"] + [b for _, b in js_bodies])

                # SPA / JS-derived API routes carry no query string in the source, so the
                # crawler never saw a parameter and no injection test ran against them
                # (Juice Shop /rest/products/search?q= got 4 requests in a whole scan).
                # Add a small, bounded set of common GET parameter names for same-origin
                # /api|/rest-style routes; every candidate is still sent only as a benign
                # canary by the normal active checks (gated by profile/safe-mode below).
                try:
                    _guess = ("q", "search", "query", "id", "name")
                    _origin_host = urlparse(final_url).netloc
                    _added = 0
                    for _u in list(urls):
                        if _added >= 40:
                            break
                        _pu = urlparse(_u)
                        if _pu.query or (_pu.netloc and _pu.netloc != _origin_host):
                            continue
                        if not re.search(r"/(?:api|rest|v[0-9]+|search|query)(?:/|$)", _pu.path, re.I):
                            continue
                        if re.search(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|map|html?)$", _pu.path, re.I):
                            continue
                        _full = _u if _pu.netloc else urljoin(final_url, _u)
                        if _full not in params:
                            params[_full] = list(_guess)
                            _added += 1
                except Exception:
                    logger.debug("parameter guessing failed", exc_info=True)

                # Safe template checks: GET/HEAD/OPTIONS only, same-origin.
                template_findings = []
                template_checks_count = 0
                if profile_cfg["templates"]:
                    template_findings, template_checks_count = await self._run_templates(client, final_url, urls, origin)
                try:
                    # Findings derived from responses the crawler/forced-browsing already received (no extra requests).
                    template_findings = list(template_findings) + self._exposure_findings(endpoints)
                except Exception:
                    logger.debug("exposure findings failed", exc_info=True)

                vuln_checks: list[VulnerabilityCheck] = []
                oob_probes: list[dict] = []
                if profile_cfg["active"]:
                    # Shared per-URL cache so the "is this text on the page
                    # regardless of input" baseline check costs one extra
                    # request per distinct URL, not one per payload tried.
                    baseline_cache: dict[str, object] = {}
                    # Bounded, non-destructive canaries against discovered query params.
                    for u, names in list(params.items())[:80]:
                        if _circuit["tripped"]:
                            break
                        for name in names[:MAX_PARAMS_PER_URL]:
                            if _circuit["tripped"]:
                                break
                            vuln_checks.append(await self._test_reflected_xss(client, u, name))
                            vuln_checks.append(await self._test_ssti(client, u, name, baseline_cache))
                            if any(hint in name.lower() for hint in COMMAND_PARAM_HINTS) and policy.mode == "destructive":
                                vuln_checks.append(await self._test_command_injection_canary(client, u, name))
                            sqli_result = await self._test_sqli_error_based(client, u, name, baseline_cache)
                            vuln_checks.append(sqli_result)
                            if not sqli_result.vulnerable:
                                # Error-based found nothing — try the blind
                                # techniques before giving up on this param.
                                # Boolean-based first (cheaper, 2 requests);
                                # time-based only if that's inconclusive too
                                # (4 requests, and the least reliable signal).
                                boolean_result = await self._test_sqli_boolean_blind(client, u, name, baseline_cache)
                                vuln_checks.append(boolean_result)
                                if not boolean_result.vulnerable:
                                    vuln_checks.append(await self._test_sqli_time_blind(client, u, name))
                            if any(hint in name.lower() for hint in LFI_PARAM_HINTS):
                                vuln_checks.append(await self._test_lfi(client, u, name, baseline_cache))
                            if any(hint in name.lower() for hint in REDIRECT_PARAM_HINTS):
                                vuln_checks.append(await self._test_open_redirect(client, u, name))
                            if oob_callback_domain and any(hint in name.lower() for hint in SSRF_PARAM_HINTS) and len(oob_probes) < 20:
                                oob_probes.append(await self._test_oob_injection(client, u, name, oob_callback_domain))
                    # Path traversal is tested independently of parameter naming so a
                    # parameter called `resource` or a REST path segment is not missed.
                    for candidate_url in list(urls)[:40]:
                        if _circuit["tripped"]: break
                        vuln_checks.append(await self._test_path_traversal(client, candidate_url))
                    if urls and not _circuit["tripped"]:
                        vuln_checks.append(await self._test_host_header(client, final_url))
                    # CRLF/header injection remains a GET-only canary and therefore
                    # stays available in safe mode.
                    for u, names in list(params.items())[:20]:
                        for name in names[:4]:
                            if _circuit["tripped"]: break
                            vuln_checks.append(await self._test_crlf_injection(client, u, name))

                    # Bounded, non-destructive canaries against discovered HTML forms
                    # (GET and POST) — this is what actually reaches classic
                    # login/search/feedback-form injection points that never show up
                    # as query-string parameters during crawling.
                    if not _circuit["tripped"]:
                        # GET-based canaries remain available in safe mode. Form
                        # submissions and default-credential probes are explicitly
                        # write-capable/authentication-affecting traffic, so they
                        # only run when the operator selected a non-safe policy.
                        vuln_checks.extend(await self._test_forms(client, forms, baseline_cache, allow_unsafe=probe_write_methods, authenticated=bool(auth_header or client.cookies or (login_result and login_result.succeeded))))
                    # Bounded default-credentials probe (max 3 well-known pairs per
                    # discovered login form) — never run under the read-only policy.
                    if not _circuit["tripped"] and policy.allow_authentication_probes:
                        vuln_checks.extend(await self._test_default_credentials(client, forms))
                    if _circuit["tripped"]:
                        crawl.setdefault("warnings", []).append(_circuit["reason"])
                    # A check that raised (timeout, budget exhausted, connection reset) is
                    # recorded as vulnerable=False. That is a coverage gap, NOT a clean
                    # result, so surface it instead of letting the scan look fully tested.
                    _failed = [c for c in vuln_checks if not c.vulnerable and str(c.evidence or "").startswith(("check failed", "Timing check unavailable"))]
                    if _failed:
                        _budget_hit = sum(1 for c in _failed if "budget exhausted" in str(c.evidence))
                        crawl.setdefault("warnings", []).append(
                            f"ACTIVE_CHECKS_INCOMPLETE: {len(_failed)} of {len(vuln_checks)} active checks did not complete"
                            + (f" ({_budget_hit} because the HTTP request budget was exhausted — raise max_requests)" if _budget_hit else "")
                            + "; these parameters were NOT proven safe.")

                if not browser_render:
                    auth_protection = analyze_auth_protection(
                        page_urls=crawl.get("urls", []),
                        forms=crawl.get("forms", []),
                        rendered_html=[],
                        xhr_requests=[],
                        responses=[],
                        origin_url=final_url,
                    )

                # Automatic Web -> API handoff. Every API-looking endpoint discovered
                # by the crawler is fed into the API engine; OpenAPI/GraphQL discovery
                # then enriches the same scan without requiring a second manual scan.
                # If a pre-crawl login (login_url/login_username/login_password) ran
                # above, `client.cookies` now holds the resulting authenticated
                # session; reuse it here so the API assessment is authenticated too
                # instead of silently falling back to anonymous testing when the
                # operator only supplied login credentials and no separate
                # auth_header/cookie.
                effective_cookie = cookie or ("; ".join(f"{n}={v}" for n, v in client.cookies.items()) or None)
                api_result = None
                api_integration = {
                    "enabled": True,
                    "seed_urls": len(api_candidates),
                    "crawler_endpoints_sent": len(endpoints),
                    "mode": "automatic_web_to_api",
                    "authenticated": bool(auth_header or effective_cookie),
                }
                if profile in {"balanced", "deep", "maximum", "passive"} and endpoints and (api_candidates or "html" in (headers_lower.get("content-type", "").lower()) or "json" in (headers_lower.get("content-type", "").lower())):
                    api_result = await self.api_scanner.scan(
                        target_url=final_url,
                        enable_graphql_introspection=(profile in {"deep", "maximum"}),
                        probe_write_methods=probe_write_methods,
                        auth_header=auth_header,
                        cookie=effective_cookie,
                        discovered_urls=urls[:MAX_ENDPOINTS],
                        discovered_api_candidates=api_candidates[:MAX_ENDPOINTS],
                        discovered_websocket_candidates=websocket_candidates,
                        max_endpoints=int(scan_policy(tenant_context.get() or "legacy")["max_endpoints"]),
                        safe_mode=safe_mode, budget=budget, destructive_confirmation=destructive_confirmation,
                        local_storage=login_result.local_storage if login_result else None,
                        oob_callback_domain=oob_callback_domain,
                    )
                    api_integration.update({
                        "probe_write_methods": probe_write_methods,
                        "api_scan_id": api_result.scan_id,
                        "api_status": api_result.status,
                        "api_endpoints": len(api_result.endpoints),
                        "openapi_discovered": api_result.openapi.discovered,
                        "graphql_discovered": api_result.graphql.discovered,
                        "websocket_candidates": len(websocket_candidates),
                        "websocket_handshakes_accepted": sum(1 for w in api_result.websockets if w.handshake_accepted),
                    })

                external_scanners = {}
                if run_external and profile in {"deep", "maximum"}:
                    profile_timeout = {
                        "quick": int(getattr(settings, "EXTERNAL_QUICK_TIMEOUT_SECONDS", 600)),
                        "standard": int(getattr(settings, "EXTERNAL_STANDARD_TIMEOUT_SECONDS", 900)),
                        "deep": int(getattr(settings, "EXTERNAL_DEEP_TIMEOUT_SECONDS", 1800)),
                        "maximum": int(getattr(settings, "EXTERNAL_MAXIMUM_TIMEOUT_SECONDS", 1800)),
                    }.get(profile, int(getattr(settings, "EXTERNAL_STANDARD_TIMEOUT_SECONDS", 900)))
                    ext_timeout = min(
                        int(getattr(settings, "EXTERNAL_DAST_TIMEOUT_SECONDS", 5400)),
                        int(settings.DEFAULT_SCAN_TIMEOUT_SECONDS),
                        profile_timeout,
                    )
                    tool_timeouts = {
                        "nuclei": ext_timeout,
                        "zap": ext_timeout,
                        "sqlmap": ext_timeout,
                        "ffuf": ext_timeout,
                        "testssl": min(ext_timeout, int(getattr(settings, "TESTSSL_TIMEOUT_SECONDS", 900))),
                    }
                    external_gate = asyncio.Semaphore(max(1, min(
                        int(getattr(settings, "EXTERNAL_ENGINE_PARALLELISM", 3)),
                        5,
                    )))
                    async def _external(name, budget_key, coro):
                        async with external_gate:
                            try:
                                await budget.acquire_external(budget_key)
                                try:
                                    return await asyncio.wait_for(coro, timeout=tool_timeouts[name] + int(getattr(settings, 'EXTERNAL_EVIDENCE_COLLECTION_TIMEOUT_SECONDS', 7200)) + 120)
                                finally:
                                    budget.release_external()
                            except Exception as exc:
                                return {"status":"FAILED","findings":[],"reason":f"{type(exc).__name__}: {str(exc)[:300]}"}

                    external_names = ("nuclei", "zap", "sqlmap", "ffuf", "testssl")
                    external_results = await asyncio.gather(
                        _external(
                            "nuclei","nuclei_engine",
                            run_nuclei(final_url,safe_mode=safe_mode,scan_profile=profile,rate_limit=int(getattr(settings,"REQUESTS_PER_SECOND",5)),timeout_seconds=tool_timeouts["nuclei"],auth_header=auth_header,cookie=effective_cookie),
                        ),
                        _external(
                            "zap","zap_engine",
                            run_zap(final_url,safe_mode=safe_mode,scan_profile=profile,timeout_seconds=tool_timeouts["zap"],auth_header=auth_header,cookie=effective_cookie),
                        ),
                        _external(
                            "sqlmap","sqlmap_engine",
                            run_sqlmap(final_url,safe_mode=safe_mode,scan_profile=profile,destructive_confirmation=destructive_confirmation,timeout_seconds=tool_timeouts["sqlmap"],auth_header=auth_header,cookie=effective_cookie),
                        ),
                        _external(
                            "ffuf","ffuf_engine",
                            run_ffuf(final_url,safe_mode=safe_mode,scan_profile=profile,timeout_seconds=tool_timeouts["ffuf"],auth_header=auth_header,cookie=effective_cookie),
                        ),
                        _external(
                            "testssl","testssl_engine",
                            run_testssl(final_url,safe_mode=safe_mode,scan_profile=profile,timeout_seconds=tool_timeouts["testssl"]),
                        ),
                    )
                    external_scanners = dict(zip(external_names, external_results))


                finished_at = datetime.now(timezone.utc)
                terminal_status = web_terminal_status("completed", external_scanners, source_intelligence)
                if any(str(w).startswith("ACTIVE_CHECKS_INCOMPLETE") for w in crawl["warnings"]):
                    terminal_status = "partial"
                return WebScanResult(
                    scan_id=scan_id, target=target_url, status=ScanStatus(terminal_status),
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
                    browser_pages_rendered=int(crawl.get("browser_pages_rendered", 0)),
                    forced_browsing_checks=forced_checks,
                    request_budget=budget.snapshot(),
                    cookie_checks=cookie_checks, cors_findings=cors_findings, cors_verification=cors_verification, cookie_details=self._cookie_details(response.headers.get_list("set-cookie")), redirect_chain=crawl.get("redirect_chain", []),
                    session_cookie=("; ".join(f"{n}={v}" for n, v in client.cookies.items()) if (login_result and login_result.succeeded) else None), passive_findings=passive_findings, scan_warnings=crawl["warnings"] + list(source_intelligence.get("warnings", []) if isinstance(source_intelligence, dict) else []),
                    api_security=api_result, api_integration=api_integration, javascript_intelligence=js_intelligence,
                    source_intelligence=source_intelligence,
                    external_scanners=external_scanners,
                    login_result=login_result, auth_protection=auth_protection,
                    oob_probes=oob_probes,
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

    async def _get_with_redirects(self, client, url: str, method="GET", *, prefer_get=False, allow_unsafe=False):
        method = method.upper()
        if method in {"POST", "PUT", "PATCH", "DELETE", "TRACE"} and not allow_unsafe:
            raise PermissionError(f"Unsafe HTTP method blocked by safe-by-default policy: {method}")
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            host = urlparse(current).hostname
            if not host:
                raise ValueError("invalid redirect target")
            verify_target_in_scope(host)
            resolve_safe_target(host)
            async with self.semaphore:
                if method.upper() == "GET" and prefer_get:
                    response = await client.get(current)
                else:
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

    async def _crawl(self, client, start_url, origin, max_pages, max_depth, seed_urls=None):
        # Traditional HTTP BFS. Sitemap/robots URLs are real crawl seeds rather
        # than telemetry-only entries, so a sitemap actually contributes to
        # assessed content.
        queue = deque([(start_url, 0)])
        for seed in seed_urls or []:
            try:
                p = urlparse(seed)
                if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) == origin:
                    queue.append((seed, 0))
            except Exception:
                continue
        seen, discovered, endpoints = set(), [], []
        forms, js_assets, bodies, warnings = [], [], [], []
        parameters: dict[str, list[str]] = {}
        redirect_chain: list[str] = []
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
                response = await self._get_with_redirects(client, self._docker_host_url(current), prefer_get=True)
            except RequestBudgetExceeded as exc:
                warnings.append(str(exc))
                break
            except Exception as exc:
                warnings.append(f"crawl failed for {current}: {exc}")
                continue
            final = str(response.url)
            if final != current:
                redirect_chain.extend([str(current), final])
            fp = urlparse(final)
            if (fp.scheme, fp.hostname, fp.port or (443 if fp.scheme == "https" else 80)) != origin:
                continue
            discovered.append(final)
            qnames = sorted(parse_qs(fp.query).keys())
            if qnames:
                parameters[final] = qnames[:MAX_PARAMS_PER_URL]
            endpoints.append(WebEndpoint(url=final, status_code=response.status_code, content_type=response.headers.get("content-type"), parameters=qnames, source="http-crawl"))
            ctype = response.headers.get("content-type", "").lower()
            body = response.content[:MAX_BODY_BYTES].decode("utf-8", errors="ignore")
            bodies.append(body[:200_000])
            if "javascript" in ctype or fp.path.lower().endswith(".js"):
                if final not in js_assets and len(js_assets) < MAX_JS_ASSETS:
                    js_assets.append(final)
            if "html" not in ctype:
                continue
            links, form_infos, assets = self._extract_html(body, final)
            forms.extend(form_infos)
            for a in assets:
                if a not in js_assets and len(js_assets) < MAX_JS_ASSETS:
                    js_assets.append(a)
            links.extend(self._extract_js_urls(body, final))
            for link in links:
                lp = urlparse(link)
                if (lp.scheme, lp.hostname, lp.port or (443 if lp.scheme == "https" else 80)) != origin:
                    continue
                verify_target_in_scope(lp.hostname)
                n = self._normalize_url(link)
                if n not in seen and len(seen) + len(queue) < max_pages * 4:
                    queue.append((link, depth + 1))
        return {"urls": list(dict.fromkeys(discovered)), "endpoints": endpoints,
                "forms": forms[:500], "javascript_assets": list(dict.fromkeys(js_assets)),
                "parameters": parameters, "bodies": bodies, "warnings": warnings, "redirect_chain": list(dict.fromkeys(redirect_chain)),
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
        default_sitemap = urljoin(root, "/sitemap.xml")
        robots, sitemap = [], []
        sitemap_queue = [default_sitemap]
        seen_sitemaps = set()
        for url, target in ((robots_url, robots),):
            try:
                r = await self._get_with_redirects(client, self._docker_host_url(url), prefer_get=True)
                if r.status_code < 400:
                    text = r.content[:500_000].decode("utf-8", errors="ignore")
                    for raw in re.findall(r"(?:Allow|Disallow|Sitemap)\s*:\s*([^#\s]+)", text, re.I):
                        absolute = urljoin(root, raw.strip())
                        if re.search(r"sitemap(?:\.xml)?(?:$|[/?])", absolute, re.I):
                            sitemap_queue.append(absolute)
                        else:
                            target.append(absolute)
            except Exception:
                logger.debug("robots.txt fetch failed for %s", url, exc_info=True)

        # Expand sitemap indexes recursively, but keep a hard bound so a broken
        # or hostile sitemap cannot turn into an unbounded crawl source.
        while sitemap_queue and len(sitemap) < 1000 and len(seen_sitemaps) < 25:
            url = sitemap_queue.pop(0)
            if url in seen_sitemaps:
                continue
            seen_sitemaps.add(url)
            try:
                r = await self._get_with_redirects(client, self._docker_host_url(url), prefer_get=True)
                if r.status_code >= 400:
                    continue
                text = r.content[:1_000_000].decode("utf-8", errors="ignore")
                locs = [urljoin(root, x.strip()) for x in re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I | re.S)]
                if re.search(r"<sitemap(?:index)?\b", text, re.I) and "<sitemap>" not in text.lower():
                    sitemap_queue.extend(x for x in locs if x not in seen_sitemaps)
                else:
                    sitemap.extend(locs)
            except Exception:
                logger.debug("sitemap fetch failed for %s", url, exc_info=True)
        return list(dict.fromkeys(robots))[:300], list(dict.fromkeys(sitemap))[:1000]

    async def _fetch_js_assets(self, client, js_assets, origin):
        results = []
        for url in list(dict.fromkeys(js_assets))[:MAX_JS_ASSETS]:
            try:
                p = urlparse(url)
                if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) != origin:
                    continue
                verify_target_in_scope(p.hostname or "")
                r = await self._get_with_redirects(client, self._docker_host_url(url), prefer_get=True)
                ctype = r.headers.get("content-type", "").lower()
                if r.status_code < 400 and ("javascript" in ctype or p.path.lower().endswith(".js")):
                    results.append((url, r.content[:1_500_000].decode("utf-8", errors="ignore")))
            except RequestBudgetExceeded:
                break
            except Exception:
                logger.debug("JS asset fetch failed for %s", url, exc_info=True)
        return results

    @staticmethod
    def _find_api_candidates(urls, js_assets, bodies):
        out = set()
        for u in urls:
            if re.search(r"/(?:api|graphql|swagger|openapi|v\d+)(?:/|$)", urlparse(u).path, re.I): out.add(u)
        for body in bodies:
            for raw in re.findall(r"['\"]((?:/|https?://)[^'\"]*(?:api|graphql|swagger|openapi|v\d+)[^'\"]*)['\"]", body, re.I):
                out.add(raw)
        return list(out)[:100]

    @staticmethod
    def _find_websocket_candidates(bodies):
        """Extract literal ws(s):// URLs referenced in crawled HTML/JS.

        Unlike REST/GraphQL, there is no reliable well-known path convention for
        WebSocket endpoints, so candidates are only ever ones actually observed in
        source — never guessed common paths.
        """
        out = set()
        for body in bodies:
            for raw in re.findall(r"wss?://[^\s'\"\\<>]+", body, re.I):
                out.add(raw.rstrip(").,;'\""))
        return list(out)[:50]

    _SENSITIVE_EXT_HIGH = (".kdbx", ".env", ".pem", ".key", ".pfx", ".p12", ".sql", ".sqlite", ".db")
    _SENSITIVE_EXT_MED = (".bak", ".old", ".orig", ".zip", ".tar", ".gz", ".tgz", ".7z", ".log", ".swp")

    @classmethod
    def _exposure_findings(cls, endpoints) -> list:
        """Turn already-observed 200 responses into findings: exposed metrics, sensitive files, directory listings."""
        out, seen = [], set()
        ok = [e for e in endpoints if getattr(e, "status_code", None) == 200 and str(getattr(e, "method", "GET")).upper() == "GET"]

        def add(tid, name, sev, url, evidence, tags):
            key = (tid, url)
            if key in seen: return
            seen.add(key)
            out.append(TemplateFinding(template_id=tid, name=name, severity_hint=sev, url=url, method="GET", status_code=200,
                                       evidence=evidence, matched=True, tags=["exposure", *tags], verified=None))

        for e in ok:
            path = urlparse(e.url).path or "/"
            ct = (e.content_type or "").lower()
            low = path.lower().rstrip("/")
            if low == "/metrics" and "text/plain" in ct:
                add("exposed-prometheus-metrics", "Prometheus metrics endpoint exposed", "Medium", e.url,
                    f"GET {path} returned 200 ({ct}); operational metrics are readable without authentication", ["metrics"])
            if not ct.startswith("text/html"):
                base = low.rsplit("/", 1)[-1]
                if low.endswith(cls._SENSITIVE_EXT_HIGH):
                    add("exposed-sensitive-file", f"Sensitive file exposed: {base}", "High", e.url,
                        f"GET {path} returned 200 ({ct or 'unknown content type'})", ["sensitive-file"])
                elif low.endswith(cls._SENSITIVE_EXT_MED):
                    add("exposed-sensitive-file", f"Backup/archive file exposed: {base}", "Medium", e.url,
                        f"GET {path} returned 200 ({ct or 'unknown content type'})", ["sensitive-file"])

        # Directory listing heuristic: a 200 HTML page whose path is the parent of >= 3 discovered resources.
        html_dirs = {}
        for e in ok:
            if (e.content_type or "").lower().startswith("text/html"):
                pth = (urlparse(e.url).path or "/").rstrip("/")
                if pth: html_dirs.setdefault(pth, e.url)
        children = {}
        for e in endpoints:
            pth = urlparse(e.url).path or "/"
            parent = pth.rstrip("/").rsplit("/", 1)[0]
            if parent: children.setdefault(parent, set()).add(pth)
        for d, url in html_dirs.items():
            n = len(children.get(d, ()))
            if n >= 3:
                add("exposed-directory-listing", f"Directory listing likely enabled: {d}/", "Medium", url,
                    f"{n} child resources were discovered directly under {d}/ and the directory itself returned 200 text/html", ["context-required", "directory-listing"])
        return out

    async def _forced_browsing(self, client, base_url, origin):
        """Bounded read-only forced browsing of high-value common paths.

        Calibrates against a soft-404 baseline first (mirrors ffuf's -ac):
        many SPAs/catch-all routers return HTTP 200 with the same shell
        page for every unknown path, which without this would make every
        one of FORCED_DISCOVERY_PATHS look like a real discovered
        endpoint. One throwaway request to a near-guaranteed-nonexistent
        path establishes what that soft-404 looks like (status + body
        length), then any real check landing on essentially the same
        response is treated as a miss, not a finding.
        """
        found = []
        checks = 0
        baseline_status, baseline_len = None, None
        try:
            probe_url = urljoin(base_url, f"/mirsad-soft-404-probe-{uuid.uuid4().hex[:10]}")
            br = await self._get_with_redirects(client, self._docker_host_url(probe_url), prefer_get=True)
            baseline_status, baseline_len = br.status_code, len(br.content)
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        for path in FORCED_DISCOVERY_PATHS:
            url = urljoin(base_url, path)
            try:
                p = urlparse(url)
                if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) != origin:
                    continue
                r = await self._get_with_redirects(client, self._docker_host_url(url), prefer_get=True)
                checks += 1
                if r.status_code >= 500:
                    continue
                is_soft_404 = (
                    baseline_status is not None and r.status_code == baseline_status
                    and abs(len(r.content) - baseline_len) < max(20, baseline_len * 0.02)
                )
                if is_soft_404:
                    continue
                found.append(WebEndpoint(url=str(r.url), status_code=r.status_code,
                                         content_type=r.headers.get("content-type"), source="forced-browsing"))
            except RequestBudgetExceeded:
                break
            except Exception:
                continue
        return found, checks

    async def _run_templates(self, client, base_url, urls, origin):
        """Run each discovery/security template exactly once against the
        scanned origin.

        Templates target fixed well-known paths (``/.well-known/security.txt``,
        ``/.git/HEAD``, ``.env``, ...), so ``urljoin(base_url, path)`` always
        resolves to the same absolute URL no matter which crawled page we
        started from. Previously this method looped over every crawled URL
        and re-ran the same absolute-path check once per URL, producing many
        duplicate "matched" findings for a single real condition (e.g. the
        same security.txt discovery repeated 7 times). Each template is now
        checked once per scan; ``urls``/``origin`` are kept in the signature
        for backward compatibility with callers/tests.
        """
        if client is None:
            return [], 0
        templates = self._load_templates()
        findings = []
        checks_count = 0
        for template in templates:
            path = template.get("path", "/")
            check_url = urljoin(base_url, path)
            try:
                verify_target_in_scope(urlparse(check_url).hostname or "")
                method = template.get("method", "GET").upper()
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    continue
                r = await self._get_with_redirects(client, self._docker_host_url(check_url), method=method, prefer_get=(method == "GET"))
                body = r.content[:500_000].decode("utf-8", errors="ignore") if method != "HEAD" else ""
                matched, evidence = self._match_template(template, r, body)
                checks_count += 1
                if matched:
                    verified = await self._verify_template_match(client, template, check_url, method)
                    findings.append(TemplateFinding(template_id=template["id"], name=template["name"], severity_hint=template.get("severity", "Info"), url=check_url, method=method, status_code=r.status_code, evidence=evidence, matched=matched, tags=template.get("tags", []), verified=verified))
            except Exception:
                continue
        return findings, checks_count

    async def _verify_template_match(self, client, template, check_url, method) -> bool | None:
        """2.2 proof-of-concept layer: before a template match is allowed to
        raise evidence_quality to HIGH, confirm it independently with a
        second non-destructive request rather than trusting a single
        observation. This catches the common false-positive causes a single
        request can't distinguish from a real finding: a transient
        edge/proxy error page that happened to match a body_regex, a flaky
        CDN response, or a WAF challenge page. It is deliberately NOT a new
        request type - same method, same URL, same safe idempotent verbs
        already enforced by the GET/HEAD/OPTIONS restriction above - so it
        adds no new attack surface or destructive risk versus the original
        check.

        Returns True (reproduced), False (did not reproduce - likely a
        transient false positive), or None if verification itself could not
        be attempted (network error, or the target fell out of scope)  -
        callers should treat None as "unverified", not as "confirmed false".
        """
        try:
            # Defense-in-depth re-check, not a redundant no-op: _run_templates
            # already verified scope once before the FIRST request, but this
            # method is also called directly by BAS replay (4.4) on a
            # schedule, potentially hours or days later - by which time the
            # tenant's authorized-target configuration may have changed. A
            # scope check that only ever ran once at original-scan-time would
            # let a scheduled replay keep hitting a host the tenant has since
            # removed from scope.
            verify_target_in_scope(urlparse(check_url).hostname or "")
            r2 = await self._get_with_redirects(client, self._docker_host_url(check_url), method=method, prefer_get=(method == "GET"))
            body2 = r2.content[:500_000].decode("utf-8", errors="ignore") if method != "HEAD" else ""
            matched2, _ = self._match_template(template, r2, body2)
            return bool(matched2)
        except Exception:
            return None

    def _load_templates(self):
        templates = []
        seen_ids: set[str] = set()
        if self.template_dir.exists():
            for path in sorted(self.template_dir.glob("*.json")):
                try:
                    tpl = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                templates.append(tpl)
                if tpl.get("id"):
                    seen_ids.add(tpl["id"])

        # 3.2: a shared, cross-tenant community template pack, distinct from
        # the tenant-scoped marketplace below. This is a plain local
        # directory of the same JSON structure used in self.template_dir
        # (e.g. populated by periodically `git pull`-ing a separate
        # community templates repo and pointing EXTERNAL_TEMPLATES_PATH at
        # its checkout) - no new format, no change to _match_template().
        # Built-in templates always win on id collision; any unreadable
        # external file is skipped rather than failing the whole load, so a
        # bad community template can never take a scan down.
        external_path = (getattr(settings, "EXTERNAL_TEMPLATES_PATH", None) or "").strip()
        if external_path:
            ext_dir = Path(external_path)
            if ext_dir.exists() and ext_dir.is_dir():
                for path in sorted(ext_dir.glob("*.json")):
                    try:
                        tpl = json.loads(path.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    tid = tpl.get("id")
                    if tid and tid in seen_ids:
                        continue  # built-in/local template with the same id takes priority
                    templates.append(tpl)
                    if tid:
                        seen_ids.add(tid)

        # 3.2: tenant-submitted custom templates (see
        # web_scan/template_marketplace.py) run alongside the built-in +
        # community set, for this tenant's scans only - never merged into
        # the shared files, and already validated/safety-screened at
        # submission time, so no extra check is needed here. Tenant
        # templates also respect the same id-priority rule (built-in/
        # community wins on collision), so a tenant can't accidentally
        # shadow a known-good shared template with a same-named one of
        # their own.
        try:
            tenant_id = tenant_context.get()
        except Exception:
            tenant_id = None
        if tenant_id:
            try:
                from app.modules.web_scan.template_marketplace import list_templates
                for tpl in list_templates(tenant_id):
                    tid = tpl.get("id")
                    if tid and tid in seen_ids:
                        continue
                    templates.append(tpl)
                    if tid:
                        seen_ids.add(tid)
            except Exception:
                logger.warning("Custom scan template failed to load for tenant %s; skipping it", tenant_id, exc_info=True)  # a broken custom template file must never break the whole scan
        return templates

    @staticmethod
    def _match_template(template, response, body):
        status = template.get("status")
        if status is not None and response.status_code not in status:
            return False, None
        for name, expected in template.get("headers", {}).items():
            value = response.headers.get(name, "")
            if expected.get("exists") is True and not value: return False, None
            # "absent" is the inverse of "exists" — needed for templates converted
            # from Nuclei's missing-security-header checks (e.g. no
            # Strict-Transport-Security), which assert a header's *absence* is
            # the vulnerable condition rather than its presence.
            if expected.get("absent") is True and value: return False, None
            if expected.get("contains") and expected["contains"].lower() not in value.lower(): return False, None
        for pattern in template.get("body_regex", []):
            if re.search(pattern, body, re.I | re.S):
                return True, f"Body matched /{pattern}/"
        # Headers-only or status-only templates (no body_regex at all) are a
        # match once we reach this point, since any header/status mismatch
        # above already returned False — previously this fallback required
        # `not template.get("headers")` too, so a template with a `headers`
        # block and no `body_regex` (e.g. a binary-content check like a
        # heapdump download) could never match regardless of the actual
        # response, silently making that template dead weight.
        if not template.get("body_regex") and (template.get("status") or template.get("headers")):
            note = "matching headers" if template.get("headers") else f"HTTP status {response.status_code}"
            return True, f"Response met the template's criteria ({note})"
        return False, None

    def _passive_response_checks(self, response, headers_lower):
        findings = []
        if "server" in headers_lower and re.search(r"/\d", headers_lower["server"]): findings.append("Server header exposes a version-like value")
        if "x-powered-by" in headers_lower: findings.append("X-Powered-By header is exposed")
        if headers_lower.get("content-type", "").startswith("text/html") and "content-security-policy" not in headers_lower: findings.append("CSP header absent on HTML response")
        if "cache-control" not in headers_lower and response.request.url.scheme == "https": findings.append("Cache-Control not explicitly set on HTTPS response")
        if "set-cookie" in headers_lower and "secure" not in headers_lower["set-cookie"].lower() and response.request.url.scheme == "https": findings.append("A Set-Cookie response was observed without Secure")
        return findings

    # (label, ssl.TLSVersion member-or-None). Members are looked up via getattr because
    # some are unavailable depending on the local OpenSSL build.
    _TLS_VERSION_PROBES = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    _WEAK_CIPHER_PATTERNS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH")

    def _check_tls_protocol_support(self, hostname, port):
        """Attempt a direct handshake pinned to each TLS version.

        This is a single, non-destructive connection per version (the same technique
        used by standard TLS auditing tools) — never a fuzzing/bruteforce loop, and no
        application data is ever sent. A version is only ever reported ENABLED when a
        full handshake with that exact version actually completed against the server.
        """
        support: dict[str, dict[str, str]] = {}
        for label, version in self._TLS_VERSION_PROBES:
            if version is None:
                support[label] = {"status": "NOT_TESTED", "reason": "Local TLS library build does not expose this protocol version"}
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # TLSv1/TLSv1.1 constants are deprecated in Python's ssl module (they are
                # insecure), but probing them deliberately is the entire point of this
                # check, so the deprecation warning is expected noise here, not a bug.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx.minimum_version = version
                    ctx.maximum_version = version
                with socket.create_connection((hostname, port), timeout=6) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        pass
                support[label] = {"status": "ENABLED"}
            except ssl.SSLError as exc:
                msg = str(exc).lower()
                if "unsupported protocol" in msg or "no protocols available" in msg or "no dice" in msg:
                    # This can be the server rejecting the version, or the local OpenSSL
                    # security policy refusing to even offer it. The two are not reliably
                    # distinguishable from this signal alone, so this is reported as
                    # NOT_TESTED rather than guessing the server disabled it.
                    support[label] = {"status": "NOT_TESTED", "reason": "Local TLS stack could not complete this handshake attempt; server support not verified"}
                else:
                    support[label] = {"status": "NOT_SUPPORTED"}
            except OSError as exc:
                support[label] = {"status": "NOT_TESTED", "reason": f"Connection error during probe: {exc}"[:200]}
            except Exception as exc:
                support[label] = {"status": "NOT_TESTED", "reason": str(exc)[:200]}
        return support

    def _check_tls(self, hostname, port):
        context = ssl.create_default_context()
        protocol_support = self._check_tls_protocol_support(hostname, port)
        weak_protocols_enabled = [label for label, info in protocol_support.items() if info.get("status") == "ENABLED" and label in ("TLSv1", "TLSv1.1")]
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock, context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert(); protocol = tls_sock.version(); cipher = tls_sock.cipher()
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if cert and cert.get("notAfter") else None
            days = (expires - datetime.now(timezone.utc)).days if expires else None
            issuer = None
            if cert and cert.get("issuer"):
                parts = {str(item[0]): str(item[1]) for rdn in cert["issuer"] for item in [rdn[0]]}
                issuer = parts.get("organizationName") or parts.get("commonName")
            weak_cipher = False
            weak_cipher_detail = None
            if cipher and cipher[0]:
                name = cipher[0].upper()
                if any(p in name for p in self._WEAK_CIPHER_PATTERNS):
                    weak_cipher = True
                    weak_cipher_detail = cipher[0]
            return TLSInfo(
                enabled=True, protocol_version=protocol, cipher_suite=cipher[0] if cipher else None,
                certificate_valid=(days is not None and days > 0), certificate_expires_at=expires, days_until_expiry=days,
                issuer=issuer, protocol_support=protocol_support, weak_protocols_enabled=weak_protocols_enabled,
                weak_cipher=weak_cipher, weak_cipher_detail=weak_cipher_detail,
            )
        except ssl.SSLCertVerificationError as exc:
            return TLSInfo(enabled=True, certificate_valid=False, error=f"شهادة غير موثوقة: {exc}", protocol_support=protocol_support, weak_protocols_enabled=weak_protocols_enabled)
        except Exception as exc:
            return TLSInfo(enabled=True, error=f"تعذّر فحص TLS: {exc}", protocol_support=protocol_support, weak_protocols_enabled=weak_protocols_enabled)

    @staticmethod
    def _check_security_headers(headers):
        checks = []
        for name in SECURITY_HEADERS_TO_CHECK:
            value = headers.get(name.lower())
            analysis = None
            if name == "Content-Security-Policy":
                if value is None: analysis = "ABSENT"
                else:
                    low = value.lower()
                    states = []
                    if "*" in value: states.append("WILDCARD")
                    if "'unsafe-inline'" in low: states.append("UNSAFE_INLINE")
                    if "'unsafe-eval'" in low: states.append("UNSAFE_EVAL")
                    if "object-src" not in low: states.append("MISSING_OBJECT_SRC")
                    if "base-uri" not in low: states.append("MISSING_BASE_URI")
                    if "frame-ancestors" not in low: states.append("MISSING_FRAME_ANCESTORS")
                    analysis = ",".join(states) if states else "VALID"
            elif name == "Strict-Transport-Security":
                if value is None: analysis = "ABSENT"
                else:
                    low=value.lower()
                    states=[]
                    m=re.search(r"max-age=(\d+)",low)
                    if not m or int(m.group(1)) < 15552000: states.append("WEAK_MAX_AGE")
                    if "includesubdomains" not in low: states.append("MISSING_INCLUDE_SUBDOMAINS")
                    analysis=",".join(states) if states else "VALID"
            elif name == "Referrer-Policy":
                if value is None: analysis = "ABSENT"
                else:
                    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
                    weak = {"unsafe-url", "no-referrer-when-downgrade"}
                    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "origin", "strict-origin"}
                    if any(t in weak for t in tokens): analysis = "WEAK"
                    elif tokens and all(t in safe for t in tokens): analysis = "VALID"
                    else: analysis = "PRESENT"
            elif name == "Permissions-Policy":
                if value is None: analysis = "ABSENT"
                elif not value.strip(): analysis = "EMPTY"
                else:
                    low = value.lower()
                    states = [f"WILDCARD_{feat.upper()}" for feat in ("camera", "microphone", "geolocation", "payment", "usb", "midi")
                              if re.search(rf"{feat}\s*=\s*\(?\s*\*\s*\)?", low)]
                    analysis = ",".join(states) if states else "VALID"
            elif name == "X-Content-Type-Options":
                if value is None: analysis = "ABSENT"
                else: analysis = "VALID" if value.strip().lower() == "nosniff" else "INVALID"
            elif name == "X-Frame-Options":
                if value is None: analysis = "ABSENT"
                else:
                    low = value.strip().lower()
                    if low in ("deny", "sameorigin"): analysis = "VALID"
                    elif low.startswith("allow-from"): analysis = "WEAK"  # deprecated, inconsistent cross-browser support
                    else: analysis = "INVALID"
            elif name == "Cross-Origin-Opener-Policy":
                if value is None: analysis = "ABSENT"
                else:
                    low = value.strip().lower()
                    if "unsafe-none" in low: analysis = "WEAK"
                    elif low in ("same-origin", "same-origin-allow-popups"): analysis = "VALID"
                    else: analysis = "PRESENT"
            elif name == "Cross-Origin-Resource-Policy":
                if value is None: analysis = "ABSENT"
                else:
                    low = value.strip().lower()
                    if low == "cross-origin": analysis = "WEAK"
                    elif low in ("same-origin", "same-site"): analysis = "VALID"
                    else: analysis = "PRESENT"
            elif name == "Cross-Origin-Embedder-Policy":
                if value is None: analysis = "ABSENT"
                else:
                    low = value.strip().lower()
                    if "unsafe-none" in low: analysis = "WEAK"
                    elif low in ("require-corp", "credentialless"): analysis = "VALID"
                    else: analysis = "PRESENT"
            else:
                analysis = "PRESENT" if value is not None else "ABSENT"
            checks.append(HeaderCheck(header_name=name, present=value is not None, value=value, analysis=analysis))
        return checks

    @staticmethod
    def _cookie_details(cookies):
        out=[]
        sensitive_names={"session","sess","sid","auth","token","access_token","refresh_token"}
        for raw in cookies:
            parts=[x.strip() for x in raw.split(";")]
            name=parts[0].split("=",1)[0].strip() or "unknown"
            attrs={p.split("=",1)[0].strip().lower(): (p.split("=",1)[1].strip() if "=" in p else True) for p in parts[1:]}
            kind="sensitive" if name.lower() in sensitive_names or any(x in name.lower() for x in ("session","token","auth")) else ("analytics" if any(x in name.lower() for x in ("ga","analytics","_gid","_fbp")) else "non-sensitive")
            out.append({"name":name,"kind":kind,"secure":bool("secure" in attrs),"httponly":bool("httponly" in attrs),"samesite":attrs.get("samesite"),"domain":attrs.get("domain"),"path":attrs.get("path"),"max_age":attrs.get("max-age"),"expires":attrs.get("expires")})
        return out

    @staticmethod
    def _check_cookies(cookies):
        out=[]
        for d in WebScanEngine._cookie_details(cookies):
            if not d["secure"]: out.append(f"Cookie '{d['name']}' لا يحتوي Secure")
            if not d["httponly"] and d["kind"] == "sensitive": out.append(f"Sensitive cookie '{d['name']}' لا يحتوي HttpOnly")
            if not d["samesite"] and d["kind"] == "sensitive": out.append(f"Sensitive cookie '{d['name']}' لا يحتوي SameSite")
            if str(d["samesite"] or "").strip().lower() == "none" and not d["secure"]:
                out.append(f"Cookie '{d['name']}' يستخدم SameSite=None بدون Secure")
        return out

    @staticmethod
    def _check_cors(headers):
        value=headers.get("access-control-allow-origin")
        return ["Access-Control-Allow-Origin: *"] if value == "*" else []

    async def _verify_cors(self, client, url, headers):
        origin = "https://mirsad.invalid"
        result={"status":"OBSERVED_ONLY","tested_origin":origin,"get":{},"options":{},"credentials":headers.get("access-control-allow-credentials",""),"methods":headers.get("access-control-allow-methods",""),"headers":headers.get("access-control-allow-headers",""),"expose_headers":headers.get("access-control-expose-headers",""),"max_age":headers.get("access-control-max-age","")}
        try:
            async with self.semaphore:
                get_r=await client.get(url, headers={"Origin":origin})
            async with self.semaphore:
                opt_r=await client.options(url, headers={"Origin":origin,"Access-Control-Request-Method":"GET","Access-Control-Request-Headers":"Authorization,Content-Type"})
            result["get"]={"status_code":get_r.status_code,"allow_origin":get_r.headers.get("access-control-allow-origin"),"allow_credentials":get_r.headers.get("access-control-allow-credentials")}
            result["options"]={"status_code":opt_r.status_code,"allow_origin":opt_r.headers.get("access-control-allow-origin"),"allow_credentials":opt_r.headers.get("access-control-allow-credentials"),"allow_methods":opt_r.headers.get("access-control-allow-methods"),"allow_headers":opt_r.headers.get("access-control-allow-headers")}
            ao=get_r.headers.get("access-control-allow-origin") or opt_r.headers.get("access-control-allow-origin")
            creds=(get_r.headers.get("access-control-allow-credentials") or opt_r.headers.get("access-control-allow-credentials") or "").lower()=="true"
            readable=bool(ao==origin or ao=="*") and get_r.status_code < 400
            body_text = get_r.text[:12000]
            sensitive_markers = ("password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "creditcard", "ssn", "privatekey", "email", '"sensitive"')
            sensitive_response = bool(ao == origin or ao == "*") and get_r.status_code < 400 and any(m in body_text.lower() for m in sensitive_markers)
            result["sensitive_response"] = sensitive_response
            result["browser_readable"] = readable
            result["status"] = "VERIFIED_RISK" if readable and creds and sensitive_response else "VERIFIED_CONFIGURATION"
        except Exception as exc:
            result["status"]="VERIFICATION_FAILED"; result["reason"]=str(exc)[:500]
        return result

    async def _get_baseline_sql_signatures(self, client, url, cache):
        """Fetch a URL completely unmodified and record which
        SQL_ERROR_SIGNATURES already appear in that baseline response.

        Some sites emit generic/verbose error pages (or embed the word
        "syntax" in ordinary content) regardless of what's sent — without
        this, a canary payload landing on such a page would look
        indistinguishable from a real SQL error. Cached per URL for the
        life of one scan so this costs exactly one extra request per
        distinct URL tested, not one per payload."""
        if url in cache:
            return cache[url]
        try:
            async with self.semaphore:
                r = await self._get_with_redirects(client, self._docker_host_url(url))
            sigs = {s for s in SQL_ERROR_SIGNATURES if s in r.text.lower()}
        except Exception:
            sigs = set()
        cache[url] = sigs
        return sigs

    @staticmethod
    def _build_poc(method: str, url: str, response, max_body: int = 1200) -> tuple[str, str]:
        """Format a compact request/response record for a finding's Proof
        of Concept — enough for a reader to manually reproduce or verify
        the result without re-running the scan. Bodies are truncated, and
        this never raises (a PoC is a nice-to-have, not something a scan
        should fail over)."""
        try:
            req_lines = [f"{method} {url}"]
            for k, v in (getattr(response, "request", None).headers.items() if getattr(response, "request", None) else []):
                if k.lower() in ("host", "user-agent", "cookie", "authorization", "content-type"):
                    req_lines.append(f"{k}: {v}")
            poc_request = "\n".join(req_lines)
            body = response.text[:max_body]
            resp_lines = [f"HTTP {response.status_code}"]
            for k in ("content-type", "content-length", "server"):
                if k in response.headers:
                    resp_lines.append(f"{k}: {response.headers[k]}")
            resp_lines.append("")
            resp_lines.append(body)
            poc_response = "\n".join(resp_lines)
            return poc_request, poc_response
        except Exception:
            return f"{method} {url}", ""

    async def _test_reflected_xss(self, client, url, param):
        payload=f'\"><script>{XSS_MARKER}</script>'
        test=self._replace_param(url,param,payload)
        try:
            r=await self._get_with_redirects(client,self._docker_host_url(test)); reflected=f"<script>{XSS_MARKER}</script>" in r.text
            poc_req, poc_resp = self._build_poc("GET", test, r) if reflected else (None, None)
            return VulnerabilityCheck(check_name="reflected_xss_canary",tested_parameter=param,payload_used=payload,vulnerable=reflected,evidence="Unescaped canary reflected in response" if reflected else None,url=url,confidence="medium" if reflected else "low",poc_request=poc_req,poc_response=poc_resp)
        except Exception as exc:
            return VulnerabilityCheck(check_name="reflected_xss_canary",tested_parameter=param,payload_used=payload,vulnerable=False,evidence=f"check failed: {exc}",url=url)

    async def _test_sqli_error_based(self, client, url, param, baseline_cache=None):
        payload="'"
        test=self._replace_param(url,param,payload)
        try:
            r=await self._get_with_redirects(client,self._docker_host_url(test)); low=r.text.lower(); sig=next((s for s in SQL_ERROR_SIGNATURES if s in low),None)
            baseline_sigs = await self._get_baseline_sql_signatures(client, url, baseline_cache) if baseline_cache is not None and sig else set()
            noisy = bool(sig) and sig in baseline_sigs
            vulnerable = bool(sig) and not noisy
            if noisy:
                evidence = f"Database error signature '{sig}' also appears in the unmodified baseline response — this page emits that text regardless of input, not a real finding"
            elif sig:
                evidence = f"Database error signature: {sig}"
            else:
                evidence = None
            poc_req, poc_resp = self._build_poc("GET", test, r) if vulnerable else (None, None)
            return VulnerabilityCheck(check_name="sqli_error_based",tested_parameter=param,payload_used=payload,vulnerable=vulnerable,evidence=evidence,url=url,confidence="medium" if vulnerable else "low",poc_request=poc_req,poc_response=poc_resp)
        except Exception as exc:
            return VulnerabilityCheck(check_name="sqli_error_based",tested_parameter=param,payload_used=payload,vulnerable=False,evidence=f"check failed: {exc}",url=url)

    async def _test_sqli_boolean_blind(self, client, url, param, baseline_cache=None):
        """Boolean-based blind SQL injection: send a condition that should
        evaluate TRUE and one that should evaluate FALSE, and compare each
        response against an unmodified baseline. A vulnerable endpoint
        typically returns a normal-looking (baseline-matching) page for the
        TRUE condition and a meaningfully different one (empty results, a
        different template branch) for FALSE — even when neither produces
        any visible database error, which is exactly what error-based
        detection above misses. Only worth the extra requests when
        error-based already came back empty, so this is called as a
        fallback, not unconditionally (see the scan() call site)."""
        true_payload, false_payload = "' AND '1'='1", "' AND '1'='2"
        true_url, false_url = self._replace_param(url, param, true_payload), self._replace_param(url, param, false_payload)
        try:
            baseline_body = await self._get_baseline_body(client, url, baseline_cache) if baseline_cache is not None else None
            if baseline_body is None:
                async with self.semaphore:
                    baseline_body = (await self._get_with_redirects(client, self._docker_host_url(url))).text
            async with self.semaphore:
                true_r = await self._get_with_redirects(client, self._docker_host_url(true_url))
            async with self.semaphore:
                false_r = await self._get_with_redirects(client, self._docker_host_url(false_url))
            base_len, true_len, false_len = len(baseline_body), len(true_r.text), len(false_r.text)
            true_matches_baseline = base_len > 0 and abs(true_len - base_len) < max(20, base_len * 0.02)
            false_differs = abs(false_len - base_len) > max(50, base_len * 0.05) and abs(false_len - true_len) > max(50, base_len * 0.05)
            vulnerable = true_matches_baseline and false_differs
            evidence = (f"TRUE condition response ({true_len} bytes) matches baseline ({base_len} bytes) but FALSE condition differs significantly ({false_len} bytes) — consistent with boolean-based blind SQL injection, needs manual confirmation"
                        if vulnerable else None)
            return VulnerabilityCheck(check_name="sqli_boolean_blind", tested_parameter=param, payload_used=f"{true_payload} / {false_payload}",
                vulnerable=vulnerable, evidence=evidence, url=url, confidence="low")
        except Exception as exc:
            return VulnerabilityCheck(check_name="sqli_boolean_blind", tested_parameter=param, payload_used=true_payload, vulnerable=False, evidence=f"check failed: {exc}", url=url)

    async def _test_sqli_time_blind(self, client, url, param):
        """Conservative last-resort timing check.

        Timing alone is noisy. Do not probe obvious static assets, establish two
        independent baselines, and require the delayed response to beat the
        median baseline by a margin. A single slow request is never promoted to
        a high-confidence finding.
        """
        p = urlparse(url)
        if re.search(r"\\.(?:css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot)(?:$|\\?)", p.path, re.I):
            return VulnerabilityCheck(check_name="sqli_time_blind", tested_parameter=param, payload_used="", vulnerable=False,
                url=url, evidence="Skipped static asset; timing-based SQLi is not meaningful for a non-dynamic resource.")

        payloads = ["' AND SLEEP(4)-- -", "' AND pg_sleep(4)-- -", "';WAITFOR DELAY '0:0:4'-- "]
        try:
            baseline_times = []
            for _ in range(2):
                async with self.semaphore:
                    t0 = time.monotonic()
                    await self._get_with_redirects(client, self._docker_host_url(url))
                    baseline_times.append(time.monotonic() - t0)
            baseline = sorted(baseline_times)[len(baseline_times)//2]

            for payload in payloads:
                test = self._replace_param(url, param, payload)
                async with self.semaphore:
                    t0 = time.monotonic()
                    await self._get_with_redirects(client, self._docker_host_url(test))
                    elapsed = time.monotonic() - t0
                # Four seconds are intentional, but require both an absolute
                # delay and a meaningful ratio over the site's own baseline.
                if elapsed - baseline >= 3.0 and elapsed >= max(4.0, baseline * 1.8):
                    # Confirm: a fresh control request must stay fast AND the same
                    # delayed payload must delay again. One-off stalls caused by
                    # engines running in parallel no longer produce a finding.
                    async with self.semaphore:
                        t0 = time.monotonic()
                        await self._get_with_redirects(client, self._docker_host_url(url))
                        control = time.monotonic() - t0
                    async with self.semaphore:
                        t0 = time.monotonic()
                        await self._get_with_redirects(client, self._docker_host_url(test))
                        repeat = time.monotonic() - t0
                    if not (control - baseline < 2.0 and repeat - baseline >= 3.0):
                        continue
                    return VulnerabilityCheck(check_name="sqli_time_blind", tested_parameter=param, payload_used=payload,
                        vulnerable=True, url=url, confidence="low",
                        evidence=f"Delayed response {elapsed:.1f}s (repeat {repeat:.1f}s) vs median baseline {baseline:.1f}s, control {control:.1f}s; requires manual confirmation.")
            return VulnerabilityCheck(check_name="sqli_time_blind", tested_parameter=param, payload_used=payloads[0], vulnerable=False, url=url,
                evidence=f"No stable timing differential; median baseline={baseline:.1f}s.")
        except Exception as exc:
            return VulnerabilityCheck(check_name="sqli_time_blind", tested_parameter=param, payload_used=payloads[0], vulnerable=False, evidence=f"Timing check unavailable: {type(exc).__name__}", url=url)

    async def _test_oob_injection(self, client, url, param, callback_domain):
        """Send one out-of-band probe: a callback URL under the operator's
        own OOB domain, injected into an SSRF-shaped parameter. This proves
        nothing by itself — it only records that the probe was sent, with a
        unique correlation ID, so the operator can check their own OOB
        dashboard (Interactsh/Collaborator/self-hosted) for an interaction
        from the target within the scan window. See
        FullScanRequest.oob_callback_domain for why this scanner doesn't
        attempt to auto-poll or auto-confirm."""
        correlation_id = uuid.uuid4().hex[:12]
        payload = f"http://{correlation_id}.{callback_domain}/"
        test_url = self._replace_param(url, param, payload)
        try:
            async with self.semaphore:
                # Fire-and-forget: don't wait long, and don't follow
                # redirects — we only need the server to have *attempted*
                # the fetch server-side, not to see any particular response.
                await client.get(self._docker_host_url(test_url), timeout=5.0, follow_redirects=False)
        except Exception:
            logger.debug("Fire-and-forget OOB probe request failed for %s", test_url, exc_info=True)  # timeouts/connection errors here are expected and irrelevant — the probe was still sent
        return {"correlation_id": correlation_id, "parameter": param, "url": url, "payload": payload, "sent_at": datetime.now(timezone.utc).isoformat()}

    async def _test_ssti(self, client, url, param, baseline_cache=None):
        """Non-destructive SSTI canary. Two fixes vs. the old check:
        1. '49' (from 7*7) is a common substring in minified CSS/JS
           (font-sizes, percentages, hex colors, hashes in ?v= query
           strings, etc.), so a bare 'is 49 in body' test is prone to
           false positives on static assets. We instead multiply two
           random 3-digit numbers per attempt, so the marker is
           effectively unique to this request.
        2. We diff against the unmodified baseline body for the same
           URL (shared cache), so a marker that's already present
           regardless of input can't trigger a false positive.
        """
        baseline_body = await self._get_baseline_body(client, url, baseline_cache) if baseline_cache is not None else ""
        a, b = random.randint(100, 999), random.randint(100, 999)
        product = str(a * b)
        payloads = [f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"<%= {a}*{b} %>"]
        for payload in payloads:
            test = self._replace_param(url, param, payload)
            try:
                async with self.semaphore:
                    r = await client.get(self._docker_host_url(test), follow_redirects=False)
                body = r.text[:200_000]
                if product in body and product not in baseline_body:
                    return VulnerabilityCheck(check_name="ssti_canary", tested_parameter=param, payload_used=payload,
                        vulnerable=True, evidence=f"Template expression evaluated to {product} in the response (absent from the unmodified baseline); manual confirmation required.", url=url, confidence="medium",
                        poc_request=f"GET {test}", poc_response=body[:2000])
            except Exception:
                continue
        return VulnerabilityCheck(check_name="ssti_canary", tested_parameter=param, payload_used="{{a*b}} / ${a*b} / <%= a*b %>", vulnerable=False, url=url)

    async def _test_command_injection_canary(self, client, url, param):
        marker = "MIRSAD_CMD_CANARY_7F31"
        payloads = [f";printf {marker}", f"$(printf {marker})"]
        for payload in payloads:
            test = self._replace_param(url, param, payload)
            try:
                async with self.semaphore:
                    r = await client.get(self._docker_host_url(test), follow_redirects=False)
                if marker in r.text[:200_000]:
                    return VulnerabilityCheck(check_name="command_injection_canary", tested_parameter=param, payload_used=payload,
                        vulnerable=True, evidence="A shell-output marker was observed in the response; independent verification is required.", url=url, confidence="medium",
                        poc_request=f"GET {test}", poc_response=r.text[:2000])
            except Exception:
                continue
        return VulnerabilityCheck(check_name="command_injection_canary", tested_parameter=param, payload_used="bounded printf marker", vulnerable=False, url=url)

    async def _test_path_traversal(self, client, url):
        p = urlparse(url)
        if not p.path or p.path == "/":
            return VulnerabilityCheck(check_name="path_traversal_canary", vulnerable=False, url=url)
        base = p.path.rsplit("/", 1)[0] or "/"
        test_path = base.rstrip("/") + "/../../../../../../etc/passwd"
        test = urlunparse(p._replace(path=test_path))
        try:
            async with self.semaphore:
                r = await client.get(self._docker_host_url(test), follow_redirects=False)
            body = r.text[:300_000]
            if "root:x:0:0:" in body:
                return VulnerabilityCheck(check_name="path_traversal_canary", payload_used="../../../../../../etc/passwd", vulnerable=True,
                    evidence="/etc/passwd signature observed in response; verify affected route and traversal boundary.", url=url, confidence="high",
                    poc_request=f"GET {test}", poc_response=body[:3000])
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        return VulnerabilityCheck(check_name="path_traversal_canary", payload_used="../../../../../../etc/passwd", vulnerable=False, url=url)

    async def _test_crlf_injection(self, client, url, param):
        payload = "mirsad-crlf%0d%0aX-Mirsad-CRLF:%20yes"
        test = self._replace_param(url, param, payload)
        try:
            async with self.semaphore:
                r = await client.get(self._docker_host_url(test), follow_redirects=False)
            marker = r.headers.get("x-mirsad-crlf") or r.headers.get("X-Mirsad-CRLF")
            if marker:
                return VulnerabilityCheck(check_name="crlf_injection", tested_parameter=param, payload_used=payload, vulnerable=True,
                    evidence=f"Injected response header observed: X-Mirsad-CRLF={marker}", url=url, confidence="high")
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        return VulnerabilityCheck(check_name="crlf_injection", tested_parameter=param, payload_used=payload, vulnerable=False, url=url)

    async def _test_host_header(self, client, url):
        probe_host = "mirsad-host-header-probe.invalid"
        try:
            async with self.semaphore:
                r = await client.get(self._docker_host_url(url), headers={"Host": probe_host}, follow_redirects=False)
            location = r.headers.get("location", "")
            if probe_host in location or probe_host in r.text[:100_000]:
                return VulnerabilityCheck(check_name="host_header_injection", payload_used=probe_host, vulnerable=True,
                    evidence="Probe host was reflected in Location/body; verify cache/password-reset impact manually.", url=url, confidence="medium")
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        return VulnerabilityCheck(check_name="host_header_injection", payload_used=probe_host, vulnerable=False, url=url)

    async def _test_open_redirect(self, client, url, param):
        """Safe, single-hop open-redirect canary.

        Only ever run against parameters whose *name* already looks
        redirect-related (never guessed/brute-forced), and never actually
        follows the redirect — it just inspects the Location header of one
        response, so no request ever reaches the probe host.
        """
        payload = OPEN_REDIRECT_PROBE
        test = self._replace_param(url, param, payload)
        try:
            async with self.semaphore:
                r = await client.get(self._docker_host_url(test))
            location = r.headers.get("location", "") or ""
            redirected_offsite = bool(location) and OPEN_REDIRECT_PROBE.rstrip("/") in location
            return VulnerabilityCheck(check_name="open_redirect_canary", tested_parameter=param, payload_used=payload,
                                       vulnerable=redirected_offsite, evidence=f"Location: {location}" if redirected_offsite else None,
                                       url=url, confidence="medium" if redirected_offsite else "low")
        except Exception as exc:
            return VulnerabilityCheck(check_name="open_redirect_canary", tested_parameter=param, payload_used=payload, vulnerable=False, evidence=f"check failed: {exc}", url=url)

    async def _render_with_browser(self, url, cookies=None, local_storage=None, max_pages=500, max_depth=8, safe_mode="safe", budget: RequestBudget | None = None):
        """Render a bounded set of SPA routes with Chromium.

        The previous implementation rendered only the root page.  This pass
        follows same-origin links discovered after JavaScript execution, waits
        for hydration, scrolls to trigger lazy-loaded content, and records
        XHR/fetch/WebSocket activity per route.  It never clicks arbitrary
        buttons or submits forms; state-changing browser actions remain outside
        the safe browser crawler and are reserved for explicit active checks.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None
        parsed_start = urlparse(url)
        origin = (parsed_start.scheme, parsed_start.hostname, parsed_start.port or (443 if parsed_start.scheme == "https" else 80))
        requests_seen: list[dict] = []
        responses_seen: list[dict] = []
        rendered_pages: list[dict] = []
        queue = deque([(url, 0)])
        seen: set[str] = set()
        browser_cookies = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                try:
                    context = await browser.new_context(ignore_https_errors=True)
                    if cookies:
                        await context.add_cookies(cookies)
                    if local_storage:
                        seed = json.dumps(local_storage)
                        await context.add_init_script(f"(() => {{ const d = {seed}; for (const k in d) window.localStorage.setItem(k, d[k]); }})();")
                    page = await context.new_page()
                    if budget:
                        async def _budget_route(route):
                            try:
                                await budget.acquire()
                            except RequestBudgetExceeded:
                                try:
                                    await route.abort()
                                except Exception:
                                    logger.debug("suppressed non-fatal error", exc_info=True)  # page already closed
                                return
                            try:
                                await route.continue_()
                            except Exception:
                                # Requests still in flight when the page/browser closes raise
                                # TargetClosedError; harmless, and it used to flood the worker log.
                                logger.debug("suppressed non-fatal error", exc_info=True)
                            finally:
                                budget.release()
                        await page.route("**/*", _budget_route)
                    async def _trace_response(resp):
                        try:
                            from app.core import execution_trace as _tr
                            rq = resp.request
                            ct = resp.headers.get("content-type", "")
                            body = None
                            if rq.resource_type in ("document", "xhr", "fetch", "script") and any(x in ct.lower() for x in ("json", "html", "text", "xml", "javascript")):
                                try:
                                    body = (await resp.body())[:8192]
                                except Exception:
                                    body = None
                            _tr.emit_http(method=rq.method, url=resp.url, request_headers=rq.headers, request_body=rq.post_data,
                                          status=resp.status, reason=resp.status_text or "", response_headers=resp.headers, response_body=body,
                                          response_content_type=ct, source="playwright", resource_type=rq.resource_type)
                        except Exception:
                            logger.debug("suppressed non-fatal error", exc_info=True)
                    page.on("response", lambda r: asyncio.ensure_future(_trace_response(r)))
                    page.on("request", lambda req: requests_seen.append({"method": req.method, "url": req.url, "resource_type": req.resource_type})
                            if req.resource_type in ("xhr", "fetch", "websocket") else None)
                    async def _capture_response(resp):
                        try:
                            if resp.request.resource_type in ("xhr", "fetch", "websocket"):
                                responses_seen.append({
                                    "method": resp.request.method, "url": resp.url,
                                    "resource_type": resp.request.resource_type,
                                    "status": resp.status,
                                    "content_type": (resp.headers.get("content-type") or "")[:120],
                                    "headers": {
                                        k.lower(): v[:300]
                                        for k, v in resp.headers.items()
                                        if k.lower() in {"retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
                                                         "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
                                                         "ratelimit-reset"}
                                    },
                                })
                        except Exception:
                            logger.debug("suppressed non-fatal error", exc_info=True)
                    page.on("response", _capture_response)
                    while queue and len(rendered_pages) < max(1, min(int(max_pages), MAX_PAGES)):
                        current, depth = queue.popleft()
                        norm = self._normalize_url(current)
                        if norm in seen or depth > max_depth:
                            continue
                        seen.add(norm)
                        cp = urlparse(current)
                        if (cp.scheme, cp.hostname, cp.port or (443 if cp.scheme == "https" else 80)) != origin:
                            continue
                        try:
                            await page.goto(current, wait_until="networkidle", timeout=30000)
                            await page.wait_for_timeout(750)
                            # Trigger common lazy/infinite-scroll mechanisms without
                            # submitting forms or activating destructive controls.
                            await page.evaluate("""async () => {
                                const max = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                                const steps = 5;
                                for (let i=1;i<=steps;i++) {
                                  window.scrollTo(0, Math.floor(max*i/steps));
                                  await new Promise(r => setTimeout(r, 180));
                                }
                                window.scrollTo(0,0);
                            }""")
                            await page.wait_for_timeout(350)
                            html = await page.content()
                            links = await page.locator("a[href], [data-route], [data-href], [routerlink], [to]").evaluate_all(
                                """els => els.flatMap(e => [
                                    e.href || e.getAttribute('data-route') || e.getAttribute('data-href') ||
                                    e.getAttribute('routerlink') || e.getAttribute('to')
                                ]).filter(Boolean)"""
                            )
                            # Dialog/navigation discovery is bounded and label-aware. We
                            # inspect safe dialog triggers but never click destructive or
                            # state-changing controls.
                            safe_dialogs = page.locator("[aria-haspopup='dialog'], [role='button'][aria-haspopup='dialog']")
                            for i in range(min(await safe_dialogs.count(), 12)):
                                try:
                                    await safe_dialogs.nth(i).click(timeout=1200)
                                    await page.wait_for_timeout(150)
                                    dialog_html = await page.content()
                                    html = dialog_html[:400_000]
                                except Exception:
                                    continue
                            rendered_pages.append({"url": current, "depth": depth, "html": html[:400_000], "links": links[:1000]})
                            for link in links:
                                lp = urlparse(str(link))
                                if (lp.scheme, lp.hostname, lp.port or (443 if lp.scheme == "https" else 80)) == origin and depth < max_depth:
                                    n = self._normalize_url(str(link))
                                    if n not in seen and len(queue) < 1000:
                                        queue.append((str(link), depth + 1))
                        except Exception as exc:
                            rendered_pages.append({"url": current, "depth": depth, "html": "", "links": [], "error": str(exc)[:300]})
                    browser_cookies = await context.cookies()
                finally:
                    # Drop route handlers still waiting on the request budget before closing, so the
                    # worker log is not flooded with "Task was destroyed but it is pending!".
                    try:
                        for _ctx in browser.contexts:
                            for _pg in _ctx.pages:
                                await _pg.unroute_all(behavior="ignoreErrors")
                    except Exception:
                        logger.debug("suppressed non-fatal error", exc_info=True)
                    await browser.close()
        except Exception:
            return None
        if not rendered_pages:
            return None
        return {"html": rendered_pages[0].get("html", ""), "pages": rendered_pages,
                "xhr_requests": requests_seen, "responses": responses_seen, "cookies": browser_cookies,
                "pages_rendered": len(rendered_pages),
                "websocket_requests": [x for x in requests_seen if x.get("resource_type") == "websocket"]}

    async def _perform_login(self, client, login_url, username, password, budget: RequestBudget | None = None):
        """Fetch login_url, locate its login form, and submit the supplied
        credentials once. httpx.AsyncClient keeps its own cookie jar, so any
        session cookie the login sets is automatically reused by every
        request the rest of this scan makes on the same client — the crawl,
        template checks, and active canaries all inherit the authenticated
        session with no further wiring needed."""
        try:
            async with self.semaphore:
                page = await self._get_with_redirects(client, self._docker_host_url(login_url), prefer_get=True)
            body = page.text[:MAX_BODY_BYTES]
            _links, forms, _assets = self._extract_html(body, str(page.url))
            login_form = next((f for f in forms if any(f.input_types.get(n) == "password" for n in f.inputs)), None)
            if login_form is None:
                # Plain HTTP fetch found no <form> at all — the classic sign
                # of an SPA login page (Angular/React/Vue) that only builds
                # its login form client-side after JS runs. Fall back to a
                # real headless browser: fill whatever password/email-like
                # inputs exist in the rendered DOM and click the first
                # submit-looking button, then hand the resulting session
                # cookies to the httpx client so the rest of the scan
                # (crawl, canaries) inherits the authenticated session.
                return await self._perform_login_via_browser(client, login_url, username, password, budget=budget)
            password_field = next(n for n in login_form.inputs if login_form.input_types.get(n) == "password")
            username_field = next((n for n in login_form.inputs if login_form.input_types.get(n, "text") in ("text", "email") and n != password_field), None)
            if not username_field:
                return LoginResult(attempted=True, succeeded=False, login_url=login_url, reason="Login form has no obvious username field")
            others = {n: "" for n in login_form.inputs if n not in (username_field, password_field) and login_form.input_types.get(n) != "submit"}
            async with self.semaphore:
                r = await self._submit_login(client, login_form, username_field, password_field, username, password, others)
            succeeded = bool(r.headers.get("set-cookie")) or r.status_code in (301, 302, 303)
            return LoginResult(attempted=True, succeeded=succeeded, login_url=login_url,
                reason=None if succeeded else "Login submission did not appear to establish a session (no new cookie, no redirect) — verify credentials")
        except Exception as exc:
            return LoginResult(attempted=True, succeeded=False, login_url=login_url, reason=f"Login attempt failed: {exc}"[:300])

    async def _perform_login_via_browser(self, client, login_url, username, password, budget: RequestBudget | None = None):
        """Browser-based login for SPA login pages that never send a <form>
        in server-rendered HTML. Uses generic, framework-agnostic selectors
        (input[type=password], and the first email/username-looking input)
        rather than anything site-specific, so it isn't tailored to one app."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return LoginResult(attempted=True, succeeded=False, login_url=login_url,
                reason="No form found in server HTML (likely an SPA login page), and Playwright is not installed to render it")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
                try:
                    context = await browser.new_context(ignore_https_errors=True)
                    page = await context.new_page()
                    if budget:
                        async def _login_budget_route(route):
                            try:
                                await budget.acquire()
                            except RequestBudgetExceeded:
                                try:
                                    await route.abort()
                                except Exception:
                                    logger.debug("suppressed non-fatal error", exc_info=True)  # page already closed
                                return
                            try:
                                await route.continue_()
                            except Exception:
                                # Requests still in flight when the page/browser closes raise
                                # TargetClosedError; harmless, and it used to flood the worker log.
                                logger.debug("suppressed non-fatal error", exc_info=True)
                            finally:
                                budget.release()
                        await page.route("**/*", _login_budget_route)
                    await page.goto(self._docker_host_url(login_url), wait_until="networkidle", timeout=20000)
                    password_input = page.locator("input[type='password']").first
                    if await password_input.count() == 0:
                        return LoginResult(attempted=True, succeeded=False, login_url=login_url,
                            reason="Rendered login page has no password input either — this may not be a login form")
                    username_input = page.locator(
                        "input[type='email'], input[name*='user' i], input[name*='email' i], input[id*='user' i], input[id*='email' i], input[type='text']"
                    ).first
                    if await username_input.count() > 0:
                        await username_input.fill(username)
                    await password_input.fill(password)
                    submit = page.locator("button[type='submit'], input[type='submit'], button:has-text('Log'), button:has-text('Sign')").first
                    if await submit.count() > 0:
                        await submit.click()
                    else:
                        await password_input.press("Enter")
                    try:
                        await page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        logger.debug("Login page networkidle wait timed out; continuing with current page state", exc_info=True)
                    browser_cookies = await context.cookies()
                    # Many SPAs (this includes well-known ones like OWASP
                    # Juice Shop) store the auth token in localStorage as a
                    # JWT rather than setting a cookie at all — a cookie-only
                    # bridge would silently miss the session entirely on
                    # those apps. Capture the *entire* localStorage snapshot
                    # (not just the token) so it can be replayed verbatim
                    # into the separate browser instance used for the main
                    # SPA-render crawl pass later.
                    local_storage: dict[str, str] = {}
                    local_storage_jwt = None
                    try:
                        raw = await page.evaluate("() => JSON.stringify(localStorage)")
                        local_storage = json.loads(raw or "{}")
                        for value in local_storage.values():
                            if isinstance(value, str) and value.count(".") == 2 and len(value) > 20:
                                local_storage_jwt = value
                                break
                    except Exception:
                        logger.debug("Failed to capture post-login localStorage snapshot", exc_info=True)
                finally:
                    # Drop route handlers still waiting on the request budget before closing, so the
                    # worker log is not flooded with "Task was destroyed but it is pending!".
                    try:
                        for _ctx in browser.contexts:
                            for _pg in _ctx.pages:
                                await _pg.unroute_all(behavior="ignoreErrors")
                    except Exception:
                        logger.debug("suppressed non-fatal error", exc_info=True)
                    await browser.close()
        except Exception as exc:
            return LoginResult(attempted=True, succeeded=False, login_url=login_url, reason=f"Browser login attempt failed: {exc}"[:300])
        succeeded = bool(browser_cookies) or bool(local_storage_jwt)
        if browser_cookies:
            for c in browser_cookies:
                try:
                    client.cookies.set(c["name"], c["value"], domain=c.get("domain") or None, path=c.get("path") or "/")
                except Exception:
                    continue
        if local_storage_jwt:
            client.headers["Authorization"] = f"Bearer {local_storage_jwt}"
        return LoginResult(attempted=True, succeeded=succeeded, login_url=login_url,
            reason=None if succeeded else "Browser login did not appear to establish a session cookie or token — verify credentials",
            local_storage=local_storage or None)

    async def _get_baseline_body(self, client, url, cache):
        """Generic cached baseline fetch (unmodified URL), reused by any
        check that needs to rule out 'this text is on the page regardless
        of input' — e.g. LFI signature false-positives on a page that
        legitimately displays sample file content."""
        if url in cache:
            return cache[url]
        try:
            async with self.semaphore:
                r = await self._get_with_redirects(client, self._docker_host_url(url))
            body = r.text
        except Exception:
            body = ""
        cache[url] = body
        return body

    async def _test_lfi(self, client, url, param, baseline_cache=None):
        """Non-destructive local-file-inclusion canary: request a handful of
        classic traversal payloads for a parameter that only ever *reads*
        well-known, non-sensitive system files, and check whether their
        known content signature shows up in the response body — but not
        already in the unmodified baseline for that URL."""
        baseline_body = await self._get_baseline_body(client, url, baseline_cache) if baseline_cache is not None else ""
        for payload, signature in LFI_SIGNATURES:
            test = self._replace_param(url, param, payload)
            try:
                async with self.semaphore:
                    r = await self._get_with_redirects(client, self._docker_host_url(test))
                if signature in r.text and signature not in baseline_body:
                    poc_req, poc_resp = self._build_poc("GET", test, r)
                    return VulnerabilityCheck(check_name="local_file_inclusion", tested_parameter=param, payload_used=payload,
                        vulnerable=True, evidence=f"Response body contains known file-content signature ({signature!r}) for payload {payload}", url=url, confidence="medium",
                        poc_request=poc_req, poc_response=poc_resp)
            except Exception as exc:
                return VulnerabilityCheck(check_name="local_file_inclusion", tested_parameter=param, payload_used=payload, vulnerable=False, evidence=f"check failed: {exc}", url=url)
        return VulnerabilityCheck(check_name="local_file_inclusion", tested_parameter=param, payload_used=LFI_SIGNATURES[0][0], vulnerable=False, url=url)

    async def _test_forms(self, client, forms, baseline_cache=None, *, allow_unsafe=False, authenticated=False):
        """Submit discovered HTML forms (GET and POST) with a bounded set of
        non-destructive canary payloads, one field at a time.

        This closes the gap where query-string-only canaries never reach
        classic form-based injection points (login forms, search boxes,
        feedback forms). Every other field in the form is filled with a
        harmless placeholder so the submission itself stays well-formed;
        only one field per request carries the payload, matching the same
        one-parameter-at-a-time methodology used for query-string canaries.
        """
        results: list[VulnerabilityCheck] = []
        form_baseline_sigs: dict[str, set] = {}
        for form in forms[:MAX_FORMS_TESTED]:
            if form.method != "GET" and authenticated:
                token_names = ("csrf", "xsrf", "anti-forgery", "authenticity", "nonce")
                has_token = any(any(t in name.lower() for t in token_names) for name in form.inputs)
                if not has_token:
                    results.append(VulnerabilityCheck(check_name="csrf_token_candidate", tested_parameter=None, payload_used=None, vulnerable=True,
                        evidence="Authenticated/state-changing form has no obvious CSRF token field. SameSite/cookie policy and server-side CSRF defenses must be verified before treating this as a vulnerability.",
                        url=form.action, method=form.method, confidence="low"))
            # GET forms are idempotent enough for the safe policy. POST forms
            # can mutate application state even with a benign canary, so they
            # require explicit non-safe operator approval.
            if form.method != "GET" and not allow_unsafe:
                continue
            injectable = [name for name in form.inputs if form.input_types.get(name, "text") not in NON_INJECTABLE_INPUT_TYPES][:MAX_FIELDS_PER_FORM]
            if not injectable:
                continue
            hidden_defaults = {name: "" for name in form.inputs if form.input_types.get(name) == "hidden"}
            baseline_key = f"{form.method} {form.action}"
            for target_field in injectable:
                for payload, kind in ((f'"><script>{XSS_MARKER}</script>', "xss"), ("'", "sqli")):
                    field_values = {**hidden_defaults, **{name: ("test" if name != target_field else payload) for name in injectable}}
                    try:
                        async with self.semaphore:
                            if form.method == "GET":
                                r = await client.get(self._docker_host_url(form.action), params=field_values)
                            else:
                                r = await client.post(self._docker_host_url(form.action), data=field_values)
                        if kind == "xss":
                            reflected = f"<script>{XSS_MARKER}</script>" in r.text
                            stored = False
                            stored_evidence = None
                            if form.method != "GET" and allow_unsafe and not reflected:
                                try:
                                    async with self.semaphore:
                                        follow = await client.get(self._docker_host_url(form.action), follow_redirects=False)
                                    stored = XSS_MARKER in follow.text
                                    if stored:
                                        stored_evidence = "XSS marker persisted and was observed on a follow-up GET to the form action; verify the exact stored rendering context."
                                except Exception:
                                    stored = False
                            vulnerable = reflected or stored
                            poc_req, poc_resp = self._build_poc(form.method, form.action, r) if vulnerable else (None, None)
                            results.append(VulnerabilityCheck(check_name="form_stored_or_reflected_xss_canary", tested_parameter=target_field, payload_used=payload,
                                vulnerable=vulnerable, evidence=(f"Unescaped canary reflected in response ({form.method} {form.action})" if reflected else stored_evidence),
                                url=form.action, confidence="high" if stored else ("medium" if reflected else "low"), poc_request=poc_req, poc_response=poc_resp))
                        else:
                            low = r.text.lower()
                            sig = next((s for s in SQL_ERROR_SIGNATURES if s in low), None)
                            if sig and baseline_cache is not None:
                                if baseline_key not in form_baseline_sigs:
                                    try:
                                        async with self.semaphore:
                                            all_benign = {**hidden_defaults, **{name: "test" for name in injectable}}
                                            base_r = (await client.get(self._docker_host_url(form.action), params=all_benign) if form.method == "GET"
                                                      else await client.post(self._docker_host_url(form.action), data=all_benign))
                                        form_baseline_sigs[baseline_key] = {s for s in SQL_ERROR_SIGNATURES if s in base_r.text.lower()}
                                    except Exception:
                                        form_baseline_sigs[baseline_key] = set()
                                noisy = sig in form_baseline_sigs[baseline_key]
                            else:
                                noisy = False
                            vulnerable = bool(sig) and not noisy
                            evidence = (f"Database error signature '{sig}' also appears with an all-benign submission — this form emits that text regardless of input, not a real finding"
                                        if (sig and noisy) else (f"Database error signature: {sig} ({form.method} {form.action})" if sig else None))
                            poc_req, poc_resp = self._build_poc(form.method, form.action, r) if vulnerable else (None, None)
                            results.append(VulnerabilityCheck(check_name="form_sqli_error_based", tested_parameter=target_field, payload_used=payload,
                                vulnerable=vulnerable, evidence=evidence, url=form.action, confidence="medium" if vulnerable else "low", poc_request=poc_req, poc_response=poc_resp))
                    except Exception as exc:
                        results.append(VulnerabilityCheck(check_name=f"form_{kind}_canary", tested_parameter=target_field, payload_used=payload,
                            vulnerable=False, evidence=f"check failed: {exc}", url=form.action))
        return results

    # A short, well-known list — this is deliberately NOT a bruteforce/credential
    # stuffing wordlist. It only ever tries the handful of pairs that are the
    # textbook "default install, never changed" combinations, capped at 3
    # attempts per login form, purely to flag installs that were never hardened.
    _DEFAULT_CREDENTIAL_PAIRS = [("admin", "admin"), ("admin", "password"), ("test", "test")]

    async def _test_default_credentials(self, client, forms):
        results: list[VulnerabilityCheck] = []
        login_forms = [f for f in forms if any(f.input_types.get(n) == "password" for n in f.inputs)][:5]
        for form in login_forms:
            password_field = next(n for n in form.inputs if form.input_types.get(n) == "password")
            username_field = next((n for n in form.inputs if form.input_types.get(n, "text") in ("text", "email") and n != password_field), None)
            if not username_field:
                continue
            others = {n: "" for n in form.inputs if n not in (username_field, password_field) and form.input_types.get(n) != "submit"}
            try:
                async with self.semaphore:
                    baseline = await self._submit_login(client, form, username_field, password_field, "sec_scan_baseline_user", "sec_scan_baseline_pw_9f3a", others)
            except Exception:
                continue
            for user, pw in self._DEFAULT_CREDENTIAL_PAIRS:
                try:
                    async with self.semaphore:
                        r = await self._submit_login(client, form, username_field, password_field, user, pw, others)
                except Exception as exc:
                    results.append(VulnerabilityCheck(check_name="default_credentials", tested_parameter=f"{username_field}/{password_field}",
                        payload_used=f"{user}:{pw}", vulnerable=False, evidence=f"check failed: {exc}", url=form.action))
                    continue
                new_session = bool(r.headers.get("set-cookie")) and r.headers.get("set-cookie") != baseline.headers.get("set-cookie")
                status_diff = (r.status_code in (301, 302, 303)) and baseline.status_code not in (301, 302, 303)
                body_len_diff = abs(len(r.text) - len(baseline.text)) > max(50, len(baseline.text) * 0.15)
                signal = new_session or status_diff or body_len_diff
                results.append(VulnerabilityCheck(check_name="default_credentials", tested_parameter=f"{username_field}/{password_field}",
                    payload_used=f"{user}:{pw}", vulnerable=signal,
                    evidence=(f"Response differed from a known-bad baseline login (status={r.status_code}, new_session={new_session}, body_len_delta={abs(len(r.text)-len(baseline.text))}) — needs manual confirmation" if signal else None),
                    url=form.action, confidence="low" if signal else "low"))
                if signal:
                    break
        return results

    @staticmethod
    async def _submit_login(client, form, username_field, password_field, user, pw, others):
        data = {**others, username_field: user, password_field: pw}
        if form.method == "GET":
            return await client.get(form.action, params=data)
        return await client.post(form.action, data=data)

    @staticmethod
    def _replace_param(url,param,new_value):
        p=urlparse(url); qs=parse_qs(p.query); qs[param]=[new_value]; return urlunparse(p._replace(query=urlencode(qs,doseq=True)))

    @staticmethod
    def _normalize_url(url):
        p=urlparse(url); return urlunparse(p._replace(fragment="",path=p.path or "/"))


WebScanner = WebScanEngine