import asyncio
import json
import logging
import time
import uuid
from urllib.parse import urlparse
from datetime import datetime, timezone

from app.modules.network_scan.scanner import NetworkScanner
from app.modules.web_scan.scanner import WebScanner
from app.modules.api_security.scanner import APISecurityScanner
from app.modules.normalizer.normalizer import normalize_bundle
from app.modules.correlator.correlator import correlate, compute_scan_diff
from app.modules.threat_intel.cve_matcher import attach_cve_matches_normalized
from app.modules.threat_intel.external_clients import gather_threat_intel
from app.modules.risk_engine.engine import bundle_score
from app.core.scan_health import external_stage_status as _classify_external_stage
from app.core.scan_coverage import build_endpoint_matrix
from app.modules.technology.fingerprint import fingerprint
from app.modules.technology.dns_tls import dns_snapshot_async, tls_snapshot_async
from app.modules.technology.subdomain_discovery import discover_subdomains
from app.modules.technology.js_analyzer import analyze_js
from app.modules.asset_inventory.inventory import inventory
from app.modules.auth_session.session import analyze_jwt
from app.modules.assessment_intelligence import build_assessment_intelligence, build_asset_links
from app.modules.external_scanners.engines import run_nuclei, run_zap, run_sqlmap, run_sqlmap_multi, run_ghauri, run_ffuf, run_testssl, run_httpx_probe, EXTERNAL_ENGINE_NAMES, _preflight as _engine_preflight, normalize_engine_target
from app.modules.advanced_security import AdvancedSecurityEngine
from app.schemas.platform import UnifiedScanResult, FullScanRequest, ScanComparison
from app.core.config import verify_target_in_scope, settings
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import step_timeout_seconds
from app.core.request_budget import RequestBudget
from app.core.architecture.history import history


def _zap_seed_urls(web, api) -> list[str]:
    """URLs found by MIRSAD's crawler/API scanner, handed to ZAP so its active
    rules have real injection points (query params, forms, API routes)."""
    urls: list[str] = []
    for ep in (getattr(web, "endpoints", None) or []):
        u = getattr(ep, "url", None)
        if u:
            urls.append(u)
    for ep in (getattr(api, "endpoints", None) or []):
        u = getattr(ep, "url", None) or getattr(ep, "path", None)
        if u and str(u).startswith("http"):
            urls.append(str(u))
    return list(dict.fromkeys(urls))



async def _with_step_timeout(coro, timeout: float, label: str, job=None, heartbeat_seconds: float = 60.0):
    """Bound a single external operation (nmap run, browser render, HTTP
    probe...) so a rate-limited/unresponsive target or a library that never
    returns can't hang the job forever. Raises TimeoutError with a clear,
    consistent message instead of letting asyncio.TimeoutError's usually
    empty str() representation obscure what happened.

    When ``job`` is given, a "still running" log line is written every
    ``heartbeat_seconds``. A quiet but healthy tool (e.g. a long Nmap run) therefore
    keeps producing real progress writes, so the stall watchdog (180s threshold)
    no longer reports a false "JOB STALLED ... tools_silent"."""
    async def _beat():
        started = time.monotonic()
        while True:
            await asyncio.sleep(heartbeat_seconds)
            try:
                job.log(f"{label} still running ({int(time.monotonic() - started)}s elapsed, limit {int(timeout)}s)")
            except Exception:
                logger.debug("suppressed non-fatal error", exc_info=True)
    beat = asyncio.ensure_future(_beat()) if job is not None else None
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(f"{label} timed out after {int(timeout)}s (target unresponsive, rate-limited, or a scan step hung)") from exc
    finally:
        if beat is not None:
            beat.cancel()


logger = logging.getLogger(__name__)



def external_stage_status(results: dict[str, dict], tool_names=EXTERNAL_ENGINE_NAMES) -> tuple[str, str]:
    """Compatible public helper; the pure classifier is shared by every entrypoint."""
    return _classify_external_stage(results, tool_names)


class ScanManager:
    def __init__(self):
        self.network = NetworkScanner()
        self.web = WebScanner()
        self.api = APISecurityScanner()
        self.advanced = AdvancedSecurityEngine()

    async def run(
        self,
        req: FullScanRequest,
        job=None,
    ) -> UnifiedScanResult:
        started = datetime.now(timezone.utc)
        # Resolve V5-V7 scan profile before any engine executes. This keeps the
        # existing scanner engines authoritative while making safety/budget
        # settings explicit and reproducible in every snapshot.
        from app.core.scan_profiles import resolve_profile
        profile = resolve_profile(req.scan_profile, req.model_dump(mode="json"))
        req = req.model_copy(update={k:v for k,v in profile.items() if hasattr(req, k)})
        scan_id = getattr(job, "job_id", None) or str(uuid.uuid4())
        # One budget is shared by every HTTP-producing module in this assessment
        # (root web/API plus subdomain assessments). This turns max_requests,
        # RPS and concurrency from metadata into enforced runtime controls.
        request_budget = RequestBudget(req.max_requests, req.requests_per_second, req.max_concurrency)
        # Bounds every individual external call below (one nmap run, one
        # page render, one DNS lookup...) independently of the overall job
        # duration, which has no limit. See policy_enforcement.step_timeout_seconds.
        step_timeout = step_timeout_seconds(tenant_context.get())

        # Structured live stages drive the dedicated progress UI. They describe
        # real scanner transitions only; no synthetic/demo progress is emitted.
        stages = [
            ("target_validation", "Target validation"),
            ("target_reachability", "Target reachability"),
            ("dns_lookup", "DNS lookup"),
            ("port_scan", "Port scanning"),
            ("service_discovery", "Service discovery"),
            ("web_crawl", "Web crawling"),
            ("source_intelligence", "Source intelligence"),
            ("source_semgrep", "Semgrep — source analysis"),
            ("source_gitleaks", "Gitleaks — secret detection"),
            ("source_trufflehog", "TruffleHog — secret detection"),
            ("source_trivy", "Trivy — vulnerability analysis"),
            ("httpx_probe", "httpx — HTTP enrichment"),
            ("external_scanners", "External detectors"),
            ("external_nuclei", "Nuclei — template vulnerability scan"),
            ("external_zap", "OWASP ZAP — DAST"),
            ("external_sqlmap", "SQLMap — SQL injection testing"),
            ("external_ghauri", "Ghauri — SQL injection cross-check"),
            ("external_ffuf", "ffuf — content discovery"),
            ("external_testssl", "testssl.sh — TLS assessment"),
            ("advanced_security", "Advanced security assessment"),
            ("api_security", "API security"),
            ("subdomain_discovery", "Subdomain discovery"),
            ("subdomain_dns", "Subdomain DNS verification"),
            ("subdomain_network", "Subdomain network scan"),
            ("subdomain_web", "Subdomain web scan"),
            ("subdomain_api", "Subdomain API security"),
            ("vulnerability_analysis", "Vulnerability analysis"),
            ("risk_correlation", "Risk correlation"),
            ("ai_validation", "AI validation"),
            ("finalize", "Finalize results"),
        ]
        if job:
            job.initialize_stages(stages)
            job.set_stage("target_validation", "running", progress=10, message="Validating target and SSRF policy")

        # Defense-in-depth:
        # Full scans must pass scope/SSRF validation before any engine executes.
        target_for_guard = (
            urlparse(req.target).hostname
            if "://" in req.target
            else req.target
        )

        verify_target_in_scope(
            target_for_guard or req.target
        )
        if job:
            job.set_stage("target_validation", "completed", progress=100, message="Target accepted")
            # Is the target up and reachable FROM THE SCANNER CONTAINERS? Answered before any engine starts.
            if getattr(settings, "PRECHECK_TARGET_REACHABLE", True) and (req.web or req.api):
                from app.modules.external_scanners.engines import probe_target_reachability
                _probe_url = req.target if "://" in req.target else "https://" + req.target
                job.set_stage("target_reachability", "running", progress=10, message="Checking the target is up and reachable from the scanner containers")
                try:
                    _probe = await probe_target_reachability(_probe_url)
                except Exception as _pexc:
                    _probe = {"checked": False, "reachable": None, "state": "unchecked", "message_ar": f"تعذّر تنفيذ فحص الوصول: {type(_pexc).__name__}"}
                job.log(f"[فحص الهدف] {_probe.get('message_ar')}")
                if _probe.get("reachable") is False:
                    if getattr(settings, "FAIL_FAST_ON_UNREACHABLE", True):
                        job.set_stage("target_reachability", "failed", progress=100, message=str(_probe.get("message_ar"))[:500])
                        raise RuntimeError(f"TARGET_UNREACHABLE[{_probe.get('state')}]: {_probe.get('message_ar')}")
                    job.set_stage("target_reachability", "partial", progress=100, message=str(_probe.get("message_ar"))[:500])
                elif _probe.get("reachable") is True:
                    job.set_stage("target_reachability", "completed", progress=100, message=str(_probe.get("message_ar"))[:500])
                else:
                    job.set_stage("target_reachability", "skipped", progress=100, message=str(_probe.get("message_ar"))[:500])
            else:
                job.set_stage("target_reachability", "skipped", progress=100, message="Reachability pre-check disabled or not applicable")
            # DNS/TLS collection happens later, after the main assessment modules.
            # Do not present it as actively running for the whole scan: that made
            # a completed scan appear to have a stuck DNS stage.
            job.set_stage("dns_lookup", "pending", progress=0, message="Waiting for DNS/TLS collection")

        web_target = (req.target if "https://" in req.target.lower() or "http://" in req.target.lower() else "https://" + req.target)

        network = None
        web = None
        api = None
        warnings = []
        module_errors: dict[str, str] = {}
        module_states: dict[str, str] = {"network": "NOT_CONFIGURED" if not req.network else "PENDING", "web": "NOT_CONFIGURED" if not req.web else "PENDING", "api": "NOT_CONFIGURED" if not req.api else "PENDING", "normalization": "PENDING", "verification": "PENDING", "risk": "PENDING", "report": "NOT_GENERATED", "subdomains": "NOT_TESTED", "nuclei": "DISABLED" if not settings.ENABLE_NUCLEI else "PENDING", "zap": "DISABLED" if not settings.ENABLE_ZAP else "PENDING", "sqlmap": "DISABLED" if not settings.ENABLE_SQLMAP else "PENDING", "ffuf": "DISABLED" if not settings.ENABLE_FFUF else "PENDING", "testssl": "DISABLED" if not settings.ENABLE_TESTSSL else "PENDING", "advanced_security": "DISABLED" if not settings.ENABLE_ADVANCED_SECURITY else "PENDING", "gemini": "DISABLED" if not req.run_gemini else "PENDING"}

        # ---------------------------------------------------------
        # Network scan
        # ---------------------------------------------------------
        if job:
            await job.checkpoint(
                "network"
                if req.network
                else "web"
                if req.web
                else "api"
                if req.api
                else "finalize"
            )

            if req.network:
                job.progress = 8
                job.set_stage("port_scan", "running", progress=10, message="Scanning configured ports")
                job.log("Network engine started")

        if req.network:
            network_target = (
                urlparse(req.target).hostname
                if "://" in req.target
                else req.target
            )

            try:
                await request_budget.acquire_external("nmap")
                try:
                    # كان الحد 3 ساعات لكل المراحل فيبقى nmap عالقًا (8%) ساعات.
                    # الآن: 30 دقيقة للبروفايلات السريعة، وساعتان فقط للثقيلة.
                    _long = str(req.network_profile or "").lower() in {"comprehensive", "udp", "vuln", "deep", "maximum"}
                    _net_cap = int(getattr(settings, "NETWORK_LONG_PROFILE_TIMEOUT_SECONDS" if _long else "NETWORK_STEP_TIMEOUT_SECONDS", 7200 if _long else 1800))
                    network = await _with_step_timeout(
                        self.network.scan(
                            network_target or req.target,
                            req.network_profile,
                            req.network_ports,
                            req.network_timing,
                        ),
                        min(step_timeout, _net_cap), "Network scan", job=job,
                    )
                finally:
                    request_budget.release_external()
                module_states["network"] = "COMPLETED"
                if job:
                    job.publish_partial_result(network=network)
                if job:
                    job.progress = 25
                    job.set_stage("port_scan", "completed", progress=100, message=f"{len(network.open_ports)} open port(s) observed")
                    job.set_stage("service_discovery", "running", progress=20, message="Parsing service/version evidence")
                    job.set_stage("service_discovery", "completed", progress=100, message=f"{len(network.open_ports)} service record(s) available")
                    job.log("Network engine completed")
            except Exception as exc:
                module_states["network"] = "FAILED"
                module_errors["network"] = str(exc)[:1000]
                warnings.append(f"Network scan failed: {str(exc)[:500]}")
                if job:
                    job.set_stage("port_scan", "failed", progress=100, message=str(exc)[:500])
                    job.set_stage("service_discovery", "failed", progress=100, message="Service discovery unavailable because network scan failed")
                    job.log(f"Network engine failed: {str(exc)[:1000]}")

        if job and not req.network:
            job.set_stage("port_scan", "skipped", progress=100, message="Network module disabled")
            job.set_stage("service_discovery", "skipped", progress=100, message="Network module disabled")

        # ---------------------------------------------------------
        # Web scan
        # ---------------------------------------------------------
        web_target = (
            req.target
            if "://" in req.target
            else "https://" + req.target
        )

        if req.web:
            if job:
                await job.checkpoint("web")
                job.progress = max(job.progress, 30)
                job.set_stage("web_crawl", "running", progress=10, message="Crawling reachable web application")
                job.log("Web engine started")

            try:
                if job:
                    job.set_stage("source_intelligence", "running", progress=20, message="Analyzing HTML, DOM, JavaScript and source maps")
                web = await _with_step_timeout(
                    self.web.scan(
                        web_target,
                        req.web_profile,
                        req.max_pages,
                        req.max_depth,
                        req.auth_header,
                        req.cookie,
                        login_url=req.login_url,
                        login_username=req.login_username,
                        login_password=req.login_password,
                        oob_callback_domain=req.oob_callback_domain,
                        probe_write_methods=req.probe_write_methods,
                        safe_mode=req.safe_mode, budget=request_budget,
                        destructive_confirmation=req.destructive_confirmation,
                    ),
                    step_timeout, "Web scan", job=job,
                )
                module_states["web"] = str(getattr(web.status, "value", web.status)).upper()
                if job:
                    job.publish_partial_result(web=web)
                if job:
                    job.progress = 55
                    job.set_stage("web_crawl", "completed", progress=100, message=f"{len(getattr(web, 'endpoints', []) or [])} endpoint(s) discovered")
                    si = getattr(web, "source_intelligence", {}) or {}
                    si_state = si.get("status", "NOT_TESTED") if isinstance(si, dict) else "NOT_TESTED"
                    si_stage = "failed" if si_state == "FAILED" else ("skipped" if si_state == "DISABLED" else "completed")
                    job.set_stage("source_intelligence", si_stage, progress=100,
                                  message=f"{int((si.get('coverage') or {}).get('endpoints', 0))} source-derived endpoint(s); {int((si.get('coverage') or {}).get('source_maps', 0))} source map(s)")
                    detector_stage_ids = {"semgrep":"source_semgrep", "gitleaks":"source_gitleaks", "trufflehog":"source_trufflehog", "trivy":"source_trivy"}
                    for detector, stage_id in detector_stage_ids.items():
                        dp = (si.get("detectors") or {}).get(detector) if isinstance(si, dict) else None
                        dst = str((dp or {}).get("status", "NOT_TESTED")) if isinstance(dp, dict) else "NOT_TESTED"
                        dstate = "completed" if dst in {"COMPLETED", "PARTIAL"} else ("failed" if dst == "FAILED" else "skipped")
                        if isinstance(dp, dict):
                            d_reason = str(dp.get("reason") or dp.get("error") or "").strip()
                            if not d_reason and dst == "FAILED":
                                d_reason = str(dp.get("stderr") or "").strip()[-200:]
                        elif isinstance(si, dict) and si.get("detectors") is None:
                            d_reason = "Detector did not run: no source files were collected from the target or source intelligence was disabled/failed"
                        else:
                            d_reason = ""
                        d_msg = f"{detector}: {dst}" + (f" — {d_reason[:300]}" if d_reason else "")
                        job.set_stage(stage_id, dstate, progress=100, message=d_msg, tool=detector)
                    ext = getattr(web, "external_scanners", {}) or {}
                    ext_failed = any(isinstance(v, dict) and v.get("status") == "FAILED" for v in ext.values())
                    ext_statuses = [str(v.get("status","UNKNOWN")) for v in ext.values() if isinstance(v, dict)]
                    ext_done = bool(ext) or req.scan_profile not in {"deep", "maximum"}
                    ext_stage = "failed" if ext_failed else ("completed" if ext_done else "skipped")
                    job.set_stage("external_scanners", ext_stage, progress=100,
                                  message=("External detector results attached; unavailable tools are recorded explicitly"
                                           if ext else "External detector layer not selected for this profile"))
                    job.log("Web engine completed")
            except Exception as exc:
                module_states["web"] = "FAILED"
                module_errors["web"] = str(exc)[:1000]
                warnings.append(f"Web scan failed: {str(exc)[:500]}")
                if job:
                    job.set_stage("web_crawl", "failed", progress=100, message=str(exc)[:500])
                    job.log(f"Web engine failed: {str(exc)[:1000]}")

            api = getattr(web, "api_security", None) if req.api else None
            if api is not None:
                module_states["api"] = "COMPLETED"
                if job:
                    job.publish_partial_result(api=api)
                    job.set_stage("api_security", "completed", progress=100,
                                  message=f"{len(getattr(api, 'endpoints', []) or [])} endpoint(s) assessed (run inline during web crawl)")

        # ---------------------------------------------------------
        # API security scan
        # ---------------------------------------------------------
        if req.api and api is None:
            if job:
                await job.checkpoint("api")
                job.progress = max(job.progress, 60)
                job.set_stage("api_security", "running", progress=10, message="Discovering and assessing API endpoints")
                job.log("API security engine started")

            try:
                api = await _with_step_timeout(
                    self.api.scan(
                        target_url=web_target,
                        spec_url=req.api_spec_url,
                        auth_header=req.auth_header,
                        cookie=req.cookie,
                        enable_graphql_introspection=req.graphql_introspection,
                        probe_write_methods=req.probe_write_methods,
                        safe_mode=req.safe_mode, budget=request_budget,
                        oob_callback_domain=req.oob_callback_domain,
                        destructive_confirmation=req.destructive_confirmation,
                    ),
                    step_timeout, "API security scan", job=job,
                )
                module_states["api"] = "COMPLETED"
                if job:
                    job.publish_partial_result(api=api)
                    job.progress = 75
                    job.set_stage("api_security", "completed", progress=100,
                                  message=f"{len(getattr(api, 'endpoints', []) or [])} endpoint(s) assessed")
                    job.log("API security engine completed")
            except Exception as exc:
                module_states["api"] = "FAILED"
                module_errors["api"] = str(exc)[:1000]
                warnings.append(f"API scan failed: {str(exc)[:500]}")
                if job:
                    job.set_stage("api_security", "failed", progress=100, message=str(exc)[:500])
                    job.log(f"API security engine failed: {str(exc)[:1000]}")

        elif api is not None and req.auth_header:
            api.jwt_analysis = type(api.jwt_analysis)(
                **analyze_jwt(req.auth_header)
            )

        if job and not req.api:
            job.set_stage("api_security", "skipped", progress=100, message="API module disabled")

        # ---------------------------------------------------------
        # Explicit differential authorization testing — this is a plain
        # differential GET test with nothing API-specific about it, so it
        # should run whenever two test identities are supplied, not only
        # when the API module happens to be enabled. Falls back to
        # web-discovered endpoints (including anything the browser-render
        # pass picked up) when the API module wasn't requested/available.
        authorization_summary = {"status": "NOT_CONFIGURED", "tested": 0, "findings": [], "reason": "Two explicit test identities are required"}
        candidate_endpoints = req.authorization_urls or (
            [e.url for e in api.endpoints[:50]] if (req.api and api and api.endpoints)
            else [e.url for e in web.endpoints[:50]] if (web and getattr(web, "endpoints", None))
            else []
        )
        if candidate_endpoints and (req.authorized_auth_header or req.authorized_cookie) and (req.unauthorized_auth_header or req.unauthorized_cookie):
            try:
                authorization_summary = await _with_step_timeout(
                    self.api.test_authorization(
                        target_url=web_target,
                        endpoints=candidate_endpoints,
                        authorized_auth_header=req.authorized_auth_header,
                        authorized_cookie=req.authorized_cookie,
                        unauthorized_auth_header=req.unauthorized_auth_header,
                        unauthorized_cookie=req.unauthorized_cookie,
                    ),
                    step_timeout, "Authorization testing",
                )
                if api:
                    api.authorization_testing = authorization_summary
                if web:
                    web.authorization_testing = authorization_summary
            except Exception as exc:
                authorization_summary = {"status": "FAILED", "tested": 0, "findings": [], "reason": str(exc)[:500]}
                if api:
                    api.authorization_testing = authorization_summary
                if web:
                    web.authorization_testing = authorization_summary

        # Optional external DAST engines. They are explicit deployment features;
        # absence/disabled state is recorded instead of pretending that Nuclei/ZAP
        # coverage happened.
        external_scanners = {}
        if req.web:
            # External detectors are part of every web-enabled full assessment.
            # Profile only changes the per-tool wall-clock budget; it no longer
            # silently removes the whole detector layer on quick/standard scans.
            profile_timeout = {
                "quick": int(getattr(settings, "EXTERNAL_QUICK_TIMEOUT_SECONDS", 600)),
                "standard": int(getattr(settings, "EXTERNAL_STANDARD_TIMEOUT_SECONDS", 900)),
                "deep": int(getattr(settings, "EXTERNAL_DEEP_TIMEOUT_SECONDS", 1800)),
                "maximum": int(getattr(settings, "EXTERNAL_MAXIMUM_TIMEOUT_SECONDS", 1800)),
            }.get(req.scan_profile, int(getattr(settings, "EXTERNAL_STANDARD_TIMEOUT_SECONDS", 900)))
            ext_timeout = min(getattr(settings, "EXTERNAL_DAST_TIMEOUT_SECONDS", 5400), step_timeout, profile_timeout)
            # Realistic per-engine caps (all configurable). A tool that hits its cap keeps its
            # partial output (status PARTIAL) instead of holding the whole scan for hours.
            tool_timeouts = {
                "nuclei": min(ext_timeout, int(getattr(settings, "NUCLEI_CAP_SECONDS", 3600))),
                "zap": min(ext_timeout, int(getattr(settings, "ZAP_CAP_SECONDS", 3600))),
                "sqlmap": min(ext_timeout, int(getattr(settings, "SQLMAP_CAP_SECONDS", 1800))),
                "ghauri": min(ext_timeout, int(getattr(settings, "GHAURI_CAP_SECONDS", 1800))),
                "ffuf": min(ext_timeout, int(getattr(settings, "FFUF_CAP_SECONDS", 3600))),
                "testssl": min(ext_timeout, getattr(settings, "TESTSSL_TIMEOUT_SECONDS", 900), int(getattr(settings, "TESTSSL_CAP_SECONDS", 900))),
            }
            if getattr(settings, "ENABLE_PROFILE_TOOL_CAPS", True):
                from app.core.config import PROFILE_TOOL_CAPS_SECONDS
                for _tool, _cap in (PROFILE_TOOL_CAPS_SECONDS.get(req.scan_profile) or {}).items():
                    if _tool in tool_timeouts:
                        tool_timeouts[_tool] = min(tool_timeouts[_tool], int(_cap))
            # Fail fast: ONE reachability check for the whole external layer. If the target cannot be
            # reached from the scanner container, every engine would otherwise discover that on its
            # own after minutes (sqlmap once burned 170 min on ConnectTimeout).
            _nuclei_tech: list[str] = []
            try:
                _nuclei_tech = fingerprint(web=web, api=api)
            except Exception:
                _nuclei_tech = []  # unknown technology => generic (full) tag set
            unreachable = {"reason": None}
            # ONE effective target for the whole external layer: loopback -> Docker-host alias, SPA fragment
            # dropped. Every engine below receives this same value, so no engine can be handed a raw
            # 127.0.0.1 again (the 2026-10-13 failure). Normalisation is idempotent inside each engine.
            try:
                ext_target = await asyncio.to_thread(normalize_engine_target, web_target)
            except Exception:
                ext_target = web_target
            try:
                _ok, _why = await _engine_preflight(ext_target, attempts=int(getattr(settings, "PREFLIGHT_ATTEMPTS", 2)))
                if not _ok and getattr(web, "status_code", None) is not None:
                    # The web crawler (same container, same network) already got an HTTP answer from this
                    # target, so a failed probe is a false alarm: never let the gate veto five engines
                    # against evidence that the target is up. The engines still run their own checks.
                    warnings.append(f"Reachability pre-check failed but the web stage reached the target (HTTP {web.status_code}); external detectors will run anyway: {_why}")
                    if job:
                        job.log(f"Preflight failed but crawler reached target (HTTP {web.status_code}) - running external detectors anyway")
                    _ok = True
                if not _ok:
                    unreachable["reason"] = _why or "target unreachable from the scanner container"
                    warnings.append(f"External detectors skipped: {unreachable['reason']}")
                    if job:
                        job.log(f"Target unreachable - external detectors skipped: {unreachable['reason']}")
            except Exception as _exc:  # never let the pre-check itself break the scan
                unreachable["reason"] = None
                warnings.append(f"External reachability pre-check could not run: {type(_exc).__name__}")
            external_parallelism = max(1, min(
                int(getattr(settings, "EXTERNAL_ENGINE_PARALLELISM", 2)),
                len(EXTERNAL_ENGINE_NAMES),
            ))
            external_gate = asyncio.Semaphore(external_parallelism)
            ext_started: dict[str, float] = {}

            def _ext_remaining() -> float:
                """Realistic remaining wall-clock for the external layer.

                Tools run `external_parallelism` at a time, so pending tools
                cost ceil(pending/parallelism) waves, and tools already
                running only cost what is left of their own budget (the old
                code summed every unfinished timeout as if they ran serially).
                """
                now_m = time.monotonic()
                running = [max(0.0, tool_timeouts.get(n, ext_timeout) - (now_m - t0))
                           for n, t0 in ext_started.items() if n not in external_scanners]
                pending = [n for n in tool_timeouts if n not in external_scanners and n not in ext_started]
                waves = -(-len(pending) // external_parallelism) if pending else 0
                return (max(running) if running else 0.0) + waves * ext_timeout
            if job:
                job.set_stage(
                    "external_scanners", "running", progress=0,
                    message=f"Starting external detectors (parallelism={external_parallelism})",
                    eta_hint_seconds=_ext_remaining(),
                )

            async def _run_external(name: str, label: str, budget_key: str, make_coro):
                """Run one external engine and log start/finish so the live log
                never looks frozen while a long tool runs."""
                began = time.monotonic()
                async with external_gate:
                    return await _run_external_inner(name, label, budget_key, make_coro)

            async def _run_external_inner(name: str, label: str, budget_key: str, make_coro):
                began = time.monotonic()
                if job:
                    await job.checkpoint("external")
                    completed_tools = len(external_scanners)
                    ext_started.setdefault(name, time.monotonic())
                    remaining = _ext_remaining()
                    tool_stage = f"external_{name}"
                    job.set_stage(tool_stage, "running", progress=0, message=f"Running {label}", eta_hint_seconds=ext_timeout, tool=name)
                    job.set_stage("external_scanners", "running", progress=int(completed_tools / len(EXTERNAL_ENGINE_NAMES) * 100), message=f"Running {label}", eta_hint_seconds=remaining, tool=name)
                    # Log this tool's OWN capped budget (tool_timeouts[name]), not the shared
                    # ext_timeout ceiling. Before this fix every "{label} started" line showed the
                    # same ext_timeout (e.g. 5400s) regardless of tool, even though sqlmap/ghauri are
                    # further capped to SQLMAP_CAP_SECONDS/GHAURI_CAP_SECONDS (1800s by default) -
                    # misleading when debugging why a tool finished or failed well under the logged figure.
                    job.log(f"{label} started (timeout {int(tool_timeouts.get(name, ext_timeout))}s)")
                recorder = None
                try:
                    if unreachable["reason"]:
                        raise RuntimeError(unreachable["reason"])
                    from app.core.canonical_artifacts import CanonicalStreamRecorder
                    if tenant_context.get():
                        # sync DB write (psycopg2) -> run off the event loop; a slow Supabase connect used to freeze the
                        # whole worker loop (JOB STALLED cause=event_loop_blocked, lag=75s, 2026-10-13).
                        recorder = await asyncio.to_thread(lambda: CanonicalStreamRecorder(scan_id=scan_id, engine=name, execution_id=getattr(job, "execution_id", None), tenant_id=tenant_context.get()))
                    await request_budget.acquire_external(budget_key)
                    try:
                        async def _stream_chunk(kind, value):
                            if recorder:
                                await recorder.on_chunk(kind, value)
                            # Nuclei emits JSONL one line at a time. Parse the
                            # line at ingestion time so live findings do not
                            # wait for process termination.
                            if name == "nuclei" and kind == "stdout" and job:
                                try:
                                    item=json.loads(value)
                                    info=item.get("info") or {}
                                    job.record_event(
                                        "finding.created",
                                        stage="external_scanners",
                                        tool="nuclei",
                                        message=str(info.get("name") or item.get("template-id") or "Nuclei finding"),
                                        payload={"template_id":item.get("template-id"),"matched_at":item.get("matched-at") or item.get("host"),"severity":info.get("severity")}
                                    )
                                    job.publish_partial_result(extra={"external_scanners": {name: {"status":"RUNNING","live_finding":True}}})
                                except (ValueError, TypeError):
                                    pass
                        coro = make_coro(_stream_chunk)
                        # outer limit = tool limit + grace, so the tool's own timeout fires first and its partial output is kept
                        external_scanners[name] = await _with_step_timeout(coro, ext_timeout + int(getattr(settings, 'EXTERNAL_EVIDENCE_COLLECTION_TIMEOUT_SECONDS', 7200)) + 120, label)
                    finally:
                        request_budget.release_external()
                    if recorder and isinstance(external_scanners.get(name), dict):
                        try:
                            eid, aids = await asyncio.to_thread(recorder.finalize, external_scanners[name])
                            external_scanners[name]["engine_result_id"] = eid
                            external_scanners[name]["raw_artifact_ids"] = aids
                        except Exception as exc:
                            # Scanner output/findings are authoritative even if
                            # persistence fails. Keep them in the scan snapshot,
                            # mark the engine PARTIAL, and expose a safe retry signal.
                            external_scanners[name]["status"] = "PARTIAL"
                            external_scanners[name]["persistence_error"] = f"{type(exc).__name__}: canonical evidence persistence failed"
                            warnings.append(f"{name}: canonical evidence persistence failed; output retained and marked partial")
                except Exception as exc:
                    existing = external_scanners.get(name)
                    if isinstance(existing, dict) and (existing.get("findings") or existing.get("stdout") or existing.get("stderr")):
                        existing["status"] = "PARTIAL"
                        existing["error"] = f"{type(exc).__name__}: external execution/persistence error"
                    else:
                        external_scanners[name] = {"status": "FAILED", "findings": [], "reason": str(exc)[:500]}
                took = int(time.monotonic() - began)
                result = external_scanners.get(name) or {}
                status = result.get("status", "FAILED") if isinstance(result, dict) else "COMPLETED"
                reason = (result.get("reason") or "")[:200] if isinstance(result, dict) else ""
                if job:
                    tool_stage = f"external_{name}"
                    tool_status = "completed" if status == "COMPLETED" else ("failed" if status == "FAILED" else ("partial" if status in {"PARTIAL", "TIMEOUT"} else "skipped" if status in {"DISABLED", "SKIPPED", "UNAVAILABLE", "NOT_INSTALLED", "NOT_CONFIGURED", "NOT_TESTED"} else "completed"))
                    _err = ""
                    if isinstance(result, dict):
                        _err = str(result.get("error") or "").strip()
                        if not _err and status == "FAILED":
                            _err = str(result.get("stderr") or "").strip()[-200:]
                    _detail = "; ".join(x for x in (reason, _err[:200]) if x)
                    job.set_stage(tool_stage, tool_status, progress=100, message=f"{label}: {status}" + (f" — {_detail}" if _detail else ""), tool=name)
                    job.record_event("external_result", tool=name, stage=tool_stage, message=f"{label}: {status}", payload={"status": status, "reason": reason, "duration_seconds": took})
                    job.publish_partial_result(extra={"external_scanners": external_scanners})
                    completed_tools = len(external_scanners)
                    remaining = _ext_remaining()
                    job.set_stage("external_scanners", "running", progress=int(completed_tools / len(EXTERNAL_ENGINE_NAMES) * 100), message=f"Finished {label}; other detectors may still be running" if completed_tools < len(EXTERNAL_ENGINE_NAMES) else "All external detectors finished", eta_hint_seconds=remaining)
                    job.log(f"{label} finished: {status} in {took}s" + (f" ({reason})" if reason else ""))

            # SQLMap runs ALONE, after both ZAP and ffuf have finished. 2026-11-01: it ran beside ZAP
            # (and then ffuf) and two of its three targets died with "Network is unreachable";
            # 2026-10-05: ZAP + Nuclei + SQLMap saturated the host bridge and made ffuf's preflight
            # time out. ffuf (the longest engine) therefore starts at once and overlaps ZAP/Nuclei,
            # which keeps the total near max(ZAP, ffuf) + SQLMap. At most EXTERNAL_ENGINE_PARALLELISM
            # engines run together (external_gate). run_sqlmap_multi also retries a dropped connection once.
            zap_finished = asyncio.Event()
            ffuf_finished = asyncio.Event()
            sqlmap_finished = asyncio.Event()

            async def _zap_then_signal():
                try:
                    return await _run_external("zap", "ZAP external scan", "zap_engine",
                        lambda on_chunk=None: run_zap(ext_target, safe_mode=req.safe_mode, scan_profile=req.scan_profile, timeout_seconds=tool_timeouts["zap"], on_chunk=on_chunk, seed_urls=_zap_seed_urls(web, api), auth_header=req.auth_header, cookie=(req.cookie or getattr(web, "session_cookie", None))))
                finally:
                    zap_finished.set()

            async def _ffuf_then_signal():
                try:
                    return await _run_external("ffuf", "ffuf content discovery", "ffuf_engine",
                        lambda on_chunk=None: run_ffuf(ext_target, safe_mode=req.safe_mode, scan_profile=req.scan_profile, timeout_seconds=tool_timeouts["ffuf"], on_chunk=on_chunk, auth_header=req.auth_header, cookie=(req.cookie or getattr(web, "session_cookie", None))))
                finally:
                    ffuf_finished.set()

            async def _sqlmap_after_zap_and_ffuf():
                try:
                    await zap_finished.wait()
                    await ffuf_finished.wait()
                    return await _run_external("sqlmap", "SQLMap external scan", "sqlmap_engine",
                            lambda on_chunk=None: run_sqlmap_multi(ext_target, web=web, api=api, safe_mode=req.safe_mode, scan_profile=req.scan_profile, destructive_confirmation=req.destructive_confirmation, timeout_seconds=tool_timeouts["sqlmap"], on_chunk=on_chunk, auth_header=req.auth_header, cookie=(req.cookie or getattr(web, "session_cookie", None))))
                finally:
                    sqlmap_finished.set()

            async def _ghauri_after_sqlmap():
                await sqlmap_finished.wait()
                return await _run_external("ghauri", "Ghauri external scan", "ghauri_engine",
                            lambda on_chunk=None: run_sqlmap_multi(ext_target, web=web, api=api, safe_mode=req.safe_mode, scan_profile=req.scan_profile, destructive_confirmation=req.destructive_confirmation, timeout_seconds=tool_timeouts["ghauri"], on_chunk=on_chunk, runner=run_ghauri, tool="ghauri", auth_header=req.auth_header, cookie=(req.cookie or getattr(web, "session_cookie", None))))

            await asyncio.gather(
                _run_external("nuclei", "Nuclei external scan", "nuclei_engine",
                    lambda on_chunk=None: run_nuclei(ext_target, detected_tech=_nuclei_tech, safe_mode=req.safe_mode, scan_profile=req.scan_profile, rate_limit=req.requests_per_second, timeout_seconds=tool_timeouts["nuclei"], on_chunk=on_chunk, auth_header=req.auth_header, cookie=(req.cookie or getattr(web, "session_cookie", None)))),
                _zap_then_signal(),
                _sqlmap_after_zap_and_ffuf(),
                _ghauri_after_sqlmap(),
                _ffuf_then_signal(),
                _run_external("testssl", "testssl TLS configuration", "testssl_engine",
                    lambda on_chunk=None: run_testssl(ext_target, safe_mode=req.safe_mode, scan_profile=req.scan_profile, timeout_seconds=tool_timeouts["testssl"], on_chunk=on_chunk)),
            )
            if job:
                ext_stage_status, ext_stage_message = external_stage_status(external_scanners)
                job.set_stage("external_scanners", ext_stage_status, progress=100, message=ext_stage_message)

        elif job:
            job.set_stage("external_scanners", "skipped", progress=100, message="Web scanning disabled")

        # Canonical evidence has already been persisted by the live recorder for
        # streamed external engines. Do NOT call persist_engine_result again: doing
        # so would create a second EngineResult/raw-artifact set for the same run.
        # Non-streamed payloads are persisted exactly once as a fallback.
        try:
            from app.core.canonical_artifacts import persist_engine_result
            tenant_id = tenant_context.get()
            if not tenant_id:
                raise PermissionError("tenant context required for canonical artifact persistence")
            for engine_name, payload in list(external_scanners.items()):
                if not isinstance(payload, dict):
                    continue
                payload["execution_id"] = getattr(job, "execution_id", None)
                if payload.get("engine_result_id"):
                    continue
                try:
                    engine_result_id, artifact_ids = persist_engine_result(scan_id=scan_id, engine=engine_name, payload=payload, execution_id=getattr(job, "execution_id", None), tenant_id=tenant_id)
                    payload["engine_result_id"] = engine_result_id
                    payload["raw_artifact_ids"] = artifact_ids
                except Exception as exc:
                    payload["status"] = "PARTIAL" if payload.get("findings") or payload.get("stdout") or payload.get("stderr") else payload.get("status", "FAILED")
                    payload["persistence_error"] = f"{type(exc).__name__}: canonical evidence persistence failed"
                    warnings.append(f"{engine_name}: canonical evidence persistence failed; scanner output retained in result and marked partial")
        except Exception as exc:
            warnings.append(f"Canonical artifact persistence unavailable: {type(exc).__name__}")

        for engine_name in EXTERNAL_ENGINE_NAMES:
            if engine_name in external_scanners:
                module_states[engine_name] = external_scanners[engine_name].get("status", "FAILED")

        advanced_security = {}
        if settings.ENABLE_ADVANCED_SECURITY and (req.web or req.api):
            try:
                if job:
                    job.set_stage("advanced_security", "running", progress=5,
                                  message="Running bounded advanced security assessment",
                                  eta_hint_seconds=min(getattr(settings, "ADVANCED_SECURITY_TIMEOUT_SECONDS", 900), step_timeout),
                                  tool="advanced_security")
                advanced_security = await _with_step_timeout(
                    self.advanced.scan(
                        web_target, web=web, api=api, safe_mode=req.safe_mode,
                        destructive_confirmation=req.destructive_confirmation,
                        auth_header=req.auth_header, cookie=req.cookie,
                        authorized_auth_header=req.authorized_auth_header,
                        authorized_cookie=req.authorized_cookie,
                        unauthorized_auth_header=req.unauthorized_auth_header,
                        unauthorized_cookie=req.unauthorized_cookie,
                        oob_callback_domain=req.oob_callback_domain, budget=request_budget,
                    ),
                    min(getattr(settings, "ADVANCED_SECURITY_TIMEOUT_SECONDS", 900), step_timeout),
                    "Advanced security assessment",
                )
                module_states["advanced_security"] = advanced_security.get("status", "COMPLETED")
                if job:
                    adv_status = str(advanced_security.get("status", "COMPLETED")).upper()
                    job.set_stage("advanced_security", "completed" if adv_status == "COMPLETED" else ("partial" if adv_status == "PARTIAL" else "failed"),
                                  progress=100, message=f"Advanced security assessment: {adv_status}", tool="advanced_security")
            except Exception as exc:
                advanced_security = {"status":"FAILED","findings":[],"reason":str(exc)[:500]}
                module_states["advanced_security"] = "FAILED"
                warnings.append(f"Advanced security assessment failed: {str(exc)[:500]}")
                if job:
                    job.set_stage("advanced_security", "failed", progress=100,
                                  message=f"Advanced security assessment failed: {type(exc).__name__}", tool="advanced_security")
        elif not settings.ENABLE_ADVANCED_SECURITY:
            advanced_security = {"status":"DISABLED","findings":[],"reason":"ENABLE_ADVANCED_SECURITY=false"}
            module_states["advanced_security"] = "DISABLED"
            if job:
                job.set_stage("advanced_security", "skipped", progress=100,
                              message="Advanced security assessment disabled", tool="advanced_security")

        # Normalize root observations now so the subdomain branch can append its
        # observations. Verification/correlation intentionally happen AFTER the
        # subdomain branch so the live pipeline matches the actual execution tree.
        raw = normalize_bundle(network, web, api, scan_id=scan_id)
        from app.modules.normalizer.normalizer import normalize_external_scanners, make_id
        raw.extend(normalize_external_scanners(external_scanners, scan_id=scan_id, target=web_target))
        # Evidence is a delivery invariant, not an optional report embellishment.
        # Keep the finding, but make a missing canonical artifact visible and
        # force the final assessment into PARTIAL rather than claiming a fully
        # reproducible result.
        provenance_issues: list[str] = []
        for finding in raw:
            if str(getattr(finding, "source_module", "")) in EXTERNAL_ENGINE_NAMES and not getattr(finding, "raw_artifact_id", None):
                provenance_issues.append(f"{finding.source_module}:{finding.finding_id}")
        if provenance_issues:
            warnings.append(f"Canonical evidence link missing for {len(provenance_issues)} external finding(s)")
        if advanced_security:
            from app.schemas.platform import NormalizedFinding, FindingEvidence
            now_adv = datetime.now(timezone.utc)
            for item in advanced_security.get("findings", [])[:2000]:
                asset = str(item.get("asset") or item.get("url") or web_target)
                title = str(item.get("title") or item.get("name") or item.get("rule_id") or "Advanced security observation")
                evidence = str(item.get("evidence") or "")[:5000]
                sev = str(item.get("severity") or "Info")
                if sev not in {"Info","Low","Medium","High","Critical"}: sev = "Info"
                raw.append(NormalizedFinding(
                    finding_id=make_id("advanced", title, asset, evidence), scan_id=scan_id,
                    source_module="advanced_security", rule_id=str(item.get("rule_id") or "MIRSAD-ADVANCED"),
                    title=title, severity=sev, confidence=0.78, status="OPEN",
                    verification_status=str(item.get("verification_status") or "DETECTED"),
                    verification_method=(f"advanced-security:{item.get('rule_id') or 'probe'}" if str(item.get("verification_status") or "DETECTED").upper() == "VERIFIED" else None),
                    verification_timestamp=(now_adv.isoformat() if str(item.get("verification_status") or "DETECTED").upper() == "VERIFIED" else None),
                    verification_reason=("The advanced engine produced a positive result from its live probe." if str(item.get("verification_status") or "DETECTED").upper() == "VERIFIED" else None),
                    method=item.get("method"), parameter=item.get("parameter"),
                    tool_version=item.get("tool_version"),
                    request=item.get("request"), response=item.get("response"),
                    raw_artifact_id=item.get("raw_artifact_id"),
                    raw_artifact_sha256=item.get("raw_artifact_sha256"),
                    verification_replay=item.get("verification_replay"),
                    security_impact=item.get("security_impact"),
                    independent_verification=item.get("independent_verification"),
                    category="advanced-dast", description="Advanced Full Assessment engine observation; independent verification may be required." ,
                    evidence=[FindingEvidence(source="advanced-security", asset=asset, evidence=evidence or "advanced engine observation", confidence=0.78)],
                    affected_asset=asset, remediation="Review the evidence and reproduce in an authorized test environment.",
                    tags=["advanced-dast", str(item.get("rule_id") or "MIRSAD-ADVANCED").lower()], first_seen=now_adv, last_seen=now_adv,
                ))
        # Quality gate: generic low-value header hardening stays in scanner telemetry,
        # but is not promoted to authoritative Findings unless explicitly requested.
        # This prevents reports from becoming a list of repetitive header warnings.
        if not req.include_hardening_findings:
            raw = [f for f in raw if not (str(getattr(f, "rule_id", "")).startswith("WEB-HEADER-CONFIG-") and str(getattr(f, "severity", "Info")) in {"Low", "Info"})]
        module_states["normalization"] = "PENDING"
        from app.modules.normalizer.normalizer import verify_findings, verify_findings_live
        if network:
            try:
                await attach_cve_matches_normalized(raw, network)
            except Exception:
                logger.debug("CVE match enrichment failed for scan %s", scan_id, exc_info=True)

        # ---------------------------------------------------------
        # Technology / DNS / TLS
        # ---------------------------------------------------------
        tech = fingerprint(
            web,
            network,
            api,
        )

        await request_budget.acquire_external("dns")
        try:
            if job:
                job.set_stage("dns_lookup", "running", progress=5, message="Resolving DNS and collecting TLS names")
            dns = await dns_snapshot_async(web_target, step_timeout)
        finally:
            request_budget.release_external()
        await request_budget.acquire_external("tls")
        try:
            tls = await tls_snapshot_async(web_target, step_timeout)
        finally:
            request_budget.release_external()
        if job:
            job.set_stage("dns_lookup", "completed", progress=100, message=f"{len(dns.get('addresses') or dns.get('ips') or [])} address(es) resolved")

        # ---------------------------------------------------------
        # Subdomain discovery + authorized lifecycle scanning
        # ---------------------------------------------------------
        cert_names = tls.get("subject_alt_names") or []
        subdomain_records = []
        if req.subdomain_discovery:
            try:
                await request_budget.acquire_external("subdomain_discovery")
                try:
                    subdomain_records = await _with_step_timeout(discover_subdomains(web_target, cert_names, max_results=req.subdomain_max_hosts), step_timeout, "Subdomain enumeration")
                finally:
                    request_budget.release_external()
            except Exception as exc:
                # Enumeration failing/timing out shouldn't take down a scan
                # that already produced valid root-target findings - degrade
                # to "no subdomains found" and keep going, same as a failed
                # network/web/api module above.
                warnings.append(f"Subdomain enumeration failed: {str(exc)[:500]}")
                if job: job.log(f"Subdomain enumeration failed: {str(exc)[:500]}")
                subdomain_records = []
        # Respect the discovery switch for every discovery source. In
        # particular, Nmap hostnames are supplemental discovery evidence and
        # must not bypass `subdomain_discovery=False`.
        base_host = (urlparse(web_target).hostname or "").lower().rstrip(".")
        try:
            import ipaddress
            base_is_ip = bool(base_host) and ipaddress.ip_address(base_host) is not None
        except ValueError:
            base_is_ip = False
        if base_is_ip:
            subdomain_records = []
            if job:
                job.set_stage("subdomain_discovery", "skipped", progress=100, message="Target is an IP address")
                for sid in ("subdomain_dns", "subdomain_network", "subdomain_web", "subdomain_api"):
                    job.set_stage(sid, "skipped", progress=100, message="Target is an IP address")
        elif req.subdomain_discovery:
            for name in (getattr(network, "hostnames", []) if network else []):
                candidate = str(name).lower().rstrip(".")
                if candidate and base_host and candidate.endswith("." + base_host) and candidate != base_host:
                    subdomain_records.append({"hostname": candidate, "method": "Nmap hostname discovery", "source": "Nmap", "evidence": f"Nmap reported hostname: {candidate}"})
        import re as _re
        valid_records = []
        for record in subdomain_records:
            host = str(record.get("hostname") or "").lower().rstrip(".")
            valid = bool(host) and len(host) <= 253 and not host.isdigit() and not all(part.isdigit() for part in host.split(".")) and not any(len(part) > 63 or not _re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in host.split("."))
            try:
                import ipaddress; valid = valid and not isinstance(ipaddress.ip_address(host), (ipaddress.IPv4Address, ipaddress.IPv6Address))
            except ValueError: pass
            if valid: valid_records.append(record)
            else:
                logger.warning("Rejecting invalid discovered hostname %r", host)
        subdomain_records = list({r["hostname"]: r for r in valid_records}.values())

        # ProjectDiscovery httpx is enrichment only: it never creates findings
        # and never triggers another scanner against discovered hosts.
        if subdomain_records and getattr(settings, "ENABLE_HTTPX_PROBE", True):
            if job: job.set_stage("httpx_probe", "running", progress=0, message=f"httpx enriching {len(subdomain_records)} discovered host(s)", tool="httpx")
            try:
                await request_budget.acquire_external("httpx_probe")
                try:
                    probe = await _with_step_timeout(
                        run_httpx_probe([r["hostname"] for r in subdomain_records], safe_mode=req.safe_mode, base_domain=base_host),
                        min(step_timeout, getattr(settings, "HTTPX_TIMEOUT_SECONDS", 300)),
                        "ProjectDiscovery httpx probe",
                    )
                finally:
                    request_budget.release_external()
                for record in subdomain_records:
                    enrichment=(probe.get("enrichment") or {}).get(record["hostname"])
                    if enrichment:
                        record["httpx"] = enrichment
                probe_status = str(probe.get("status") or "FAILED").upper()
                stage_status = {
                    "COMPLETED": "completed",
                    "PARTIAL": "partial",
                    "FAILED": "failed",
                    "DISABLED": "skipped",
                    "SKIPPED": "skipped",
                    "UNAVAILABLE": "skipped",
                    "NOT_TESTED": "skipped",
                }.get(probe_status, "partial")
                if job:
                    detail = str(probe.get("reason") or "").strip()
                    message = f"httpx: {probe_status}; enriched {len((probe.get('enrichment') or {}))} host(s)"
                    if detail:
                        message += f" — {detail[:250]}"
                    job.set_stage("httpx_probe", stage_status, progress=100, message=message, tool="httpx")
            except Exception as exc:
                warnings.append(f"httpx enrichment failed: {str(exc)[:300]}")
                if job: job.set_stage("httpx_probe", "failed", progress=100, message=f"httpx: {str(exc)[:300]}", tool="httpx")
        elif job:
            if not getattr(settings, "ENABLE_HTTPX_PROBE", True):
                _httpx_skip_reason = "HTTPX enrichment disabled (ENABLE_HTTPX_PROBE=false)"
            elif not subdomain_records:
                _httpx_skip_reason = "No eligible discovered subdomains/hosts; HTTPX had no inputs"
            else:
                _httpx_skip_reason = "No discovered hosts passed scope and host validation"
            job.set_stage("httpx_probe", "skipped", progress=100, message=_httpx_skip_reason, tool="httpx")

        subdomain_scans: list[dict] = []
        subdomain_assets: list[dict] = []
        subdomain_raw = []
        if subdomain_records and req.scan_discovered_subdomains and any((req.subdomain_dns_verification, req.subdomain_network_scan, req.subdomain_web_scan, req.subdomain_api_security)):
            module_states["subdomains"] = "PENDING"
            if job:
                await job.checkpoint("subdomains")
                job.set_stage("subdomain_discovery", "completed", progress=100, message=f"Discovered {len(subdomain_records)} host(s)")
                for sid, enabled, label in (("subdomain_dns", req.subdomain_dns_verification, "Subdomain DNS verification"), ("subdomain_network", req.subdomain_network_scan and req.network, "Subdomain network scan"), ("subdomain_web", req.subdomain_web_scan and req.web, "Subdomain web scan"), ("subdomain_api", req.subdomain_api_security and req.api, "Subdomain API security")):
                    job.set_stage(sid, "pending" if enabled else "skipped", progress=0 if enabled else 100, message=label + (" enabled" if enabled else " disabled by assessment policy"))
                job.log(f"Subdomain assessment policy: DNS={req.subdomain_dns_verification}, network={req.subdomain_network_scan and req.network}, web={req.subdomain_web_scan and req.web}, api={req.subdomain_api_security and req.api}")
            # 2026-10-09: this used to be a strictly sequential `for` loop — one
            # subdomain's full DNS+network+web+API pass (including its own
            # nuclei/zap/sqlmap/ffuf/testssl fan-out inside self.web.scan)
            # completed before the next subdomain even started. For a target
            # with 10-15 discovered hosts at ~1-2h per host that alone made up
            # the large majority of total scan time. Each host is otherwise
            # fully independent, so they now run concurrently under a bounded
            # semaphore (SUBDOMAIN_SCAN_CONCURRENCY) instead — same per-host
            # logic, same findings, same cancellation checkpoint, just no
            # longer serialized behind one another.
            subdomain_gate = asyncio.Semaphore(max(1, int(getattr(settings, "SUBDOMAIN_SCAN_CONCURRENCY", 4))))
            completed_count = {"n": 0}

            async def _scan_one_subdomain(idx: int, record: dict):
                async with subdomain_gate:
                    # Was previously only checked once before this loop started
                    # ("subdomains" checkpoint above), so a cancel requested while
                    # deep into a large subdomain list had no deterministic,
                    # cooperative point to be noticed at loop level — it relied
                    # entirely on task.cancel() interrupting whatever inner await
                    # happened to be in flight. One checkpoint per subdomain gives
                    # a hard upper bound (one subdomain's worth of checks) on how
                    # long a requested cancellation can take to actually stop
                    # outbound traffic to the target.
                    if job: await job.checkpoint(f"subdomains[{idx}/{len(subdomain_records)}]")
                    host = str(record.get("hostname") or "").lower().rstrip(".")
                    item = {**record, "status": "DISCOVERED_ONLY", "target": host, "findings_count": 0,
                            "tests": {"dns_verification": "NOT_SELECTED", "network": "NOT_SELECTED", "web": "NOT_SELECTED", "api": "NOT_SELECTED"}}
                    if not host or host == base_host:
                        item["status"] = "SKIPPED"; item["reason"] = "Invalid or root hostname"
                        return item, [], None
                    sd_raw: list = []
                    asset = None
                    try:
                        verify_target_in_scope(host)
                        # Discovery and authorization are independent from test selection.
                        if req.subdomain_dns_verification:
                            item["tests"]["dns_verification"] = "RUNNING"
                            if job: job.set_stage("subdomain_dns", "running", progress=min(100, int(completed_count["n"] / max(1, len(subdomain_records)) * 100)), message=f"DNS verification: {host}")
                            sd_web_target = f"{urlparse(web_target).scheme}://{host}"
                            sd_dns = await dns_snapshot_async(sd_web_target, step_timeout)
                            if sd_dns.get("addresses") or sd_dns.get("ips"):
                                item["ips"] = sd_dns.get("addresses") or sd_dns.get("ips") or []
                                item["tests"]["dns_verification"] = "COMPLETED"
                            else:
                                item["tests"]["dns_verification"] = "FAILED"
                                item["reason"] = sd_dns.get("error") or "No DNS address returned"
                        else:
                            sd_web_target = f"{urlparse(web_target).scheme}://{host}"
                            sd_dns = {}

                        sd_network = sd_web = sd_api = None
                        if req.subdomain_network_scan and req.network:
                            item["tests"]["network"] = "RUNNING"
                            if job: job.set_stage("subdomain_network", "running", progress=min(100, int(completed_count["n"] / max(1, len(subdomain_records)) * 100)), message=f"Network scan: {host}")
                            sd_network = await _with_step_timeout(
                                self.network.scan(host, req.network_profile, req.network_ports, req.network_timing),
                                step_timeout, f"Subdomain network scan ({host})",
                            )
                            item["tests"]["network"] = "COMPLETED" if getattr(sd_network, "status", None) else "FAILED"
                            item["network_status"] = getattr(sd_network, "status", None)
                            item["open_ports"] = [getattr(x, "port", None) for x in (getattr(sd_network, "open_ports", []) or []) if str(getattr(x, "state", "")).lower() == "open"]

                        if req.subdomain_web_scan and req.web:
                            item["tests"]["web"] = "RUNNING"
                            if job: job.set_stage("subdomain_web", "running", progress=min(100, int(completed_count["n"] / max(1, len(subdomain_records)) * 100)), message=f"Web scan: {host}")
                            sd_web = await _with_step_timeout(
                                self.web.scan(sd_web_target, req.web_profile, req.subdomain_max_pages, req.subdomain_max_depth, req.auth_header, req.cookie, oob_callback_domain=req.oob_callback_domain, probe_write_methods=req.probe_write_methods, safe_mode=req.safe_mode, budget=request_budget, destructive_confirmation=req.destructive_confirmation),
                                step_timeout, f"Subdomain web scan ({host})",
                            )
                            item["tests"]["web"] = "COMPLETED" if getattr(sd_web, "status_code", None) is not None else "FAILED"
                            item["http_reachable"] = getattr(sd_web, "status_code", None) is not None
                            item["web_status_code"] = getattr(sd_web, "status_code", None)

                        if req.subdomain_api_security and req.api:
                            item["tests"]["api"] = "RUNNING"
                            if job: job.set_stage("subdomain_api", "running", progress=min(100, int(completed_count["n"] / max(1, len(subdomain_records)) * 100)), message=f"API security: {host}")
                            seed_urls = list(getattr(sd_web, "discovered_urls", []) or []) if sd_web else []
                            seed_api = list(getattr(sd_web, "api_candidates", []) or []) if sd_web else []
                            sd_api = await _with_step_timeout(
                                self.api.scan(target_url=sd_web_target, auth_header=req.auth_header, cookie=req.cookie, enable_graphql_introspection=req.graphql_introspection, probe_write_methods=req.probe_write_methods, discovered_urls=seed_urls, discovered_api_candidates=seed_api, safe_mode=req.safe_mode, budget=request_budget, oob_callback_domain=req.oob_callback_domain, destructive_confirmation=req.destructive_confirmation),
                                step_timeout, f"Subdomain API security scan ({host})",
                            )
                            item["tests"]["api"] = "COMPLETED"

                        selected = [v for v in item["tests"].values() if v not in {"NOT_SELECTED"}]
                        ran_any = any(v == "COMPLETED" for v in selected)
                        item["status"] = "SCANNED" if ran_any else "DISCOVERED_ONLY"
                        sd_raw = normalize_bundle(sd_network, sd_web, sd_api, scan_id=scan_id)
                        if sd_network:
                            try: await attach_cve_matches_normalized(sd_raw, sd_network)
                            except Exception: logger.debug("CVE match enrichment failed for subdomain %s", host, exc_info=True)
                        item["findings_count"] = len(sd_raw)
                        if ran_any:
                            asset = {"target": host, "ips": item.get("ips", []), "ports": item.get("open_ports", []), "services": [getattr(x, "service_name", None) for x in (getattr(sd_network, "open_ports", []) or []) if getattr(x, "service_name", None)] if sd_network else [], "technologies": fingerprint(sd_web, sd_network, sd_api), "web_apps": [sd_web_target] if sd_web and getattr(sd_web, "status_code", None) is not None else [], "apis": list(getattr(sd_api, "endpoints", []) or []) if sd_api else [], "endpoints": list(getattr(sd_web, "endpoints", []) or []) if sd_web else []}
                    except Exception as exc:
                        item["status"] = "SKIPPED_SCOPE" if exc.__class__.__name__ == "ScopeViolationError" else "FAILED"
                        item["reason"] = str(exc)[:500]
                    completed_count["n"] += 1
                    if job:
                        job.progress = min(82, 60 + int(completed_count["n"] / max(1, len(subdomain_records)) * 20))
                        job.log(f"Subdomain {completed_count['n']}/{len(subdomain_records)}: {host} -> {item['status']}")
                    return item, sd_raw, asset

            for item, sd_raw, asset in await asyncio.gather(
                *(_scan_one_subdomain(idx, record) for idx, record in enumerate(subdomain_records, start=1))
            ):
                subdomain_scans.append(item)
                if sd_raw: subdomain_raw.extend(sd_raw)
                if asset: subdomain_assets.append(asset)
            from app.core.scan_health import subdomain_assessment_status
            module_states["subdomains"] = subdomain_assessment_status(subdomain_scans)
            if job:
                for sid in ("subdomain_dns", "subdomain_network", "subdomain_web", "subdomain_api"):
                    current = next((x for x in (job._progress_meta().get("stages") or []) if x.get("id") == sid), None)
                    if current and current.get("status") in {"running", "pending"}: job.set_stage(sid, "completed" if current.get("status") == "running" else "skipped", progress=100, message="Completed" if current.get("status") == "running" else "all discovered hosts failed before this test")
        elif subdomain_records:
            module_states["subdomains"] = "NOT_TESTED"
            if job:
                job.set_stage("subdomain_discovery", "completed" if req.subdomain_discovery else "skipped", progress=100, message=f"{len(subdomain_records)} discovered; no subdomain assessment tests selected")
                for sid, label in (("subdomain_dns", "Subdomain DNS verification"), ("subdomain_network", "Subdomain network scan"), ("subdomain_web", "Subdomain web scan"), ("subdomain_api", "Subdomain API security")):
                    job.set_stage(sid, "skipped", progress=100, message=f"{label} not selected")
        else:
            module_states["subdomains"] = "COMPLETED"
            if job: job.set_stage("subdomain_discovery", "completed" if req.subdomain_discovery else "skipped", progress=100, message="No subdomains discovered" if req.subdomain_discovery else "Subdomain discovery disabled")
            if job:
                for sid in ("subdomain_dns", "subdomain_network", "subdomain_web", "subdomain_api"):
                    job.set_stage(sid, "skipped", progress=100, message="No discovered subdomains")

        # Merge the independently scanned subdomain observations into the same
        # normalization/verification/correlation pipeline as the root target.
        # This is intentionally done after subdomain assessment so their findings
        # cannot be lost or scored separately.
        if subdomain_raw:
            if not req.include_hardening_findings:
                subdomain_raw = [f for f in subdomain_raw if not (str(getattr(f, "rule_id", "")).startswith("WEB-HEADER-CONFIG-") and str(getattr(f, "severity", "Info")) in {"Low", "Info"})]
            raw.extend(subdomain_raw)

        # ---------------------------------------------------------
        # Normalization / verification / correlation (root + subdomains)
        # ---------------------------------------------------------
        if job:
            await job.checkpoint("normalizer")
            job.progress = max(job.progress, 82)
            job.set_stage("vulnerability_analysis", "running", progress=15, message="Normalizing root and discovered-subdomain observations")
            job.log("Normalizer started")

        module_states["normalization"] = "COMPLETED"
        verification_summary = await verify_findings_live(raw, scan_id=scan_id, tenant_id=tenant_context.get(), job_id=getattr(job, "job_id", None))
        module_states["verification"] = verification_summary["state"]
        from app.core.finding_confirmation import apply_confirmation_gate
        verification_summary["confirmation"] = apply_confirmation_gate(raw)
        from app.core.scan_health import verification_stage_status
        module_states["verification"] = verification_stage_status(
            verification_summary["state"], verification_summary["confirmation"]
        )
        verification_summary["state"] = module_states["verification"]
        if job:
            job.set_stage("vulnerability_analysis", "completed", progress=100, message=f"{len(raw)} normalized finding observation(s)")

        if job:
            job.set_stage("risk_correlation", "running", progress=20, message="Correlating findings and calculating risk")
        findings = correlate(raw)
        # Preserve every original observation as a source row; correlation never
        # replaces secondary evidence with the primary finding.
        try:
            from app.core.canonical_artifacts import attach_finding_sources
            for engine_name, payload in external_scanners.items():
                if not isinstance(payload, dict) or not payload.get("engine_result_id"):
                    continue
                engine_findings=[f for f in findings if f.source_module == engine_name or any(src.get("engine") == engine_name for src in getattr(f,"sources",[]))]
                if engine_findings:
                    attach_finding_sources(scan_id=scan_id, findings=engine_findings, engine_result_id=payload["engine_result_id"], artifact_ids=payload.get("raw_artifact_ids") or [], engine=engine_name, execution_id=payload.get("execution_id"), tenant_id=tenant_context.get())
        except Exception as exc:
            warnings.append(f"Finding provenance persistence failed: {type(exc).__name__}")
            provenance_issues.append(f"finding-source-write:{type(exc).__name__}")
        module_states["risk"] = "COMPLETED"
        if job:
            job.set_stage("risk_correlation", "completed", progress=100, message=f"{len(findings)} correlated finding(s)")

        ai_validation = {}
        if req.run_gemini:
            if job:
                await job.checkpoint("ai_validation")
                job.progress = max(job.progress, 91)
                job.set_stage("ai_validation", "running", progress=10, message="Validating prioritized findings")
            try:
                from app.modules.ai_analysis.analyzer import AIAnalyzer, AIAnalyzerConfigError, AIAnalyzerResponseError
                ai_validation = await AIAnalyzer().validate_findings(findings, req.language)
            except (AIAnalyzerConfigError, AIAnalyzerResponseError) as exc:
                # AI is an enrichment/validation layer, never a reason to fail an
                # otherwise completed security assessment. In particular Google
                # may reject the server egress IP with 400 FAILED_PRECONDITION
                # when its geo classification does not permit Gemini API use.
                reason = str(exc)[:500]
                ai_validation = {"status": "fallback", "reason": reason, "validated": [],
                                 "authoritative": "rule_based"}
                warnings.append("Gemini validation unavailable; rule-based findings remain authoritative.")
                if job:
                    ai_stage_status = "skipped" if reason == "gemini_region_unsupported" else "completed"
                    ai_stage_message = "Gemini unavailable for server region; rule-based validation retained" if ai_stage_status == "skipped" else "AI unavailable; deterministic validation retained"
                    job.set_stage("ai_validation", ai_stage_status, progress=100, message=ai_stage_message)
            else:
                if job:
                    if ai_validation.get("reason_code") == "gemini_region_unsupported":
                        job.set_stage("ai_validation", "skipped", progress=100, message="Gemini unavailable for server region; rule-based validation retained")
                    elif ai_validation.get("status") == "fallback":
                        job.set_stage("ai_validation", "completed", progress=100, message="AI unavailable; deterministic validation retained")
                    else:
                        job.set_stage("ai_validation", "completed", progress=100, message="AI validation completed")
        elif job:
            job.set_stage("ai_validation", "skipped", progress=100, message="Gemini validation disabled")

        if job:
            job.progress = max(job.progress, 94)
            job.log("Correlation and risk calculation completed")

        try:
            intel = await gather_threat_intel(
                target_for_guard,
                dns.get("addresses")
                or dns.get("ips")
                or [],
                budget=request_budget,
            )
        except Exception:
            intel = {}

        js = (
            web.javascript_intelligence
            if web
            else analyze_js([], [])
        )
        assessment_intelligence = build_assessment_intelligence(
            web=web, api=api, findings=findings,
            js_bodies=list((getattr(web, "javascript_intelligence", {}) or {}).get("bodies", []) or []),
            technologies=tech,
            # 2.1: cheap shared-IP adjacency between the root target and its
            # assessed subdomains, built right here from DNS data this
            # function already has - lets attack_chain_hints() trace chains
            # across hosts sharing infrastructure during the scan itself,
            # without needing the full attack-surface graph (which is only
            # ever built on-demand by the /assessment routes, well after
            # this point in the pipeline).
            asset_links=build_asset_links(
                [{"host": base_host, "ips": dns.get("addresses") or dns.get("ips") or []}]
                + [{"host": a.get("target"), "ips": a.get("ips") or []} for a in subdomain_assets]
            ),
        )

        # ---------------------------------------------------------
        # Asset surface information
        # ---------------------------------------------------------
        ports = (
            [
                f"{p.port}/{p.protocol}"
                for p in network.open_ports
            ]
            if network
            else []
        )

        endpoints = (
            [
                e.url
                for e in web.endpoints
            ]
            if web
            else []
        )

        services = (
            [
                f"{p.service_name or 'unknown'}:"
                f"{p.port}/{p.protocol}"
                for p in (
                    network.open_ports
                    if network
                    else []
                )
            ]
        )

        apis = (
            [
                e.url
                for e in (
                    api.endpoints
                    if api
                    else []
                )
            ]
        )

        web_apps = (
            [web.target]
            if web
            else []
        )

        finding_ids = [
            f.finding_id
            for f in findings
        ]

        # ---------------------------------------------------------
        # TLS certificate expiration
        # ---------------------------------------------------------
        tls_expiry_days = None

        if tls.get("notAfter"):
            try:
                from email.utils import parsedate_to_datetime

                expiry = parsedate_to_datetime(
                    tls["notAfter"]
                )

                if expiry.tzinfo is None:
                    expiry = expiry.replace(
                        tzinfo=timezone.utc
                    )

                now_utc = datetime.now(timezone.utc)

                tls_expiry_days = max(
                    0,
                    (expiry - now_utc).days,
                )

                # Explicitly guarantee integer output.
                tls_expiry_days = int(
                    tls_expiry_days
                )

            except (
                TypeError,
                ValueError,
                OverflowError,
                AttributeError,
            ):
                tls_expiry_days = None

        # ---------------------------------------------------------
        # Build asset surface snapshot
        #
        # IMPORTANT:
        # tls_expiry_days is intentionally a scalar integer.
        # It must NOT be converted to a list here.
        # ---------------------------------------------------------
        asset_snapshot = {
            "ips": (
                dns.get("addresses")
                or dns.get("ips")
                or []
            ),
            "ports": ports,
            "services": services,
            "technologies": tech,
            "web_apps": web_apps,
            "apis": apis,
            "endpoints": endpoints,
            "dns_records": (
                dns.get("records")
                or dns.get("addresses")
                or []
            ),
            "tls_protocol": (
                [tls.get("protocol")]
                if tls.get("protocol")
                else []
            ),
            "tls_not_after": tls.get(
                "notAfter"
            ),
            "tls_expiry_days": tls_expiry_days,
        }

        # ---------------------------------------------------------
        # Update asset inventory
        # ---------------------------------------------------------
        asset = await inventory.upsert(
            req.target,
            tech,
            ports,
            endpoints,
            ips=(
                dns.get("addresses")
                or dns.get("ips")
                or []
            ),
            services=services,
            web_apps=web_apps,
            apis=apis,
            finding_ids=finding_ids,
            snapshot=asset_snapshot,
        )

        # ---------------------------------------------------------
        # Finalize
        # ---------------------------------------------------------
        finished = datetime.now(timezone.utc)

        if job:
            await job.checkpoint("finalize")
            job.progress = 96
            job.set_stage("finalize", "running", progress=20, message="Persisting immutable scan snapshot")
            job.log("Finalizing scan result")

        requested = [name for name, enabled in (("network", req.network), ("web", req.web), ("api", req.api)) if enabled]
        terminal_failed = [name for name in requested if module_states[name] in {"FAILED"}]
        partial_stages = [name for name in requested if module_states[name] in {"PARTIAL", "UNAVAILABLE"}]
        # External engines and provenance are part of the requested web/API
        # assessment. Do not let a green crawler mask a failed detector or an
        # evidence chain that cannot be audited.
        external_failed = [name for name, payload in external_scanners.items()
                           if isinstance(payload, dict) and str(payload.get("status", "")).upper() == "FAILED"]
        external_partial = [name for name, payload in external_scanners.items()
                            if isinstance(payload, dict) and str(payload.get("status", "")).upper() in {"PARTIAL", "TIMEOUT", "BUDGET_EXHAUSTED"}]
        if module_states.get("subdomains") in {"FAILED", "PARTIAL", "BUDGET_EXHAUSTED", "TIMEOUT"}:
            external_partial.append("subdomains")
        if module_states.get("advanced_security") in {"FAILED", "PARTIAL", "NOT_TESTED", "BUDGET_EXHAUSTED", "TIMEOUT"}:
            external_partial.append("advanced_security")
        if module_states.get("verification") in {"FAILED", "PARTIAL", "NOT_TESTED"}:
            external_partial.append("verification")
        if provenance_issues:
            external_partial.append("evidence_reconciliation")
        completed = [name for name in requested if module_states[name] == "COMPLETED"]
        all_skipped = requested and all(module_states[name] in {"SKIPPED", "DISABLED", "NOT_CONFIGURED", "UNAVAILABLE"} for name in requested)
        scan_status = "failed" if (terminal_failed or external_failed) and not completed and not partial_stages and not external_partial else ("partial" if terminal_failed or partial_stages or external_failed or external_partial else ("skipped" if all_skipped else "completed"))
        def cap(name, state, reason=None):
            return {"status": state, **({"reason": reason} if reason else {})}
        capabilities = {}
        if req.network:
            ns = module_states["network"]
            for name in ("discovery", "dns", "network", "http_methods"):
                capabilities[name] = cap(name, ns, module_errors.get("network") if ns == "FAILED" else None)
        else:
            for name in ("discovery", "dns", "network", "http_methods"): capabilities[name] = cap(name, "NOT_TESTED", "Network module disabled")
        if req.web:
            ws = module_states["web"]
            for name in ("http", "security_headers", "web", "cookies", "cors", "redirects", "javascript", "technology_detection", "cache", "tls"):
                capabilities[name] = cap(name, ws, module_errors.get("web") if ws == "FAILED" else None)
            scan_warnings = list(getattr(web, "scan_warnings", []) or []) if web else []
            challenge_warning = next((w for w in scan_warnings if "challenge" in w.lower() or "bot" in w.lower() or "blocked" in w.lower()), None)
            capabilities["web_scan_quality"] = cap("web_scan_quality", "PARTIAL" if challenge_warning else "COMPLETED", challenge_warning)
        else:
            for name in ("http", "security_headers", "web", "cookies", "cors", "redirects", "javascript", "technology_detection", "cache", "tls"): capabilities[name] = cap(name, "NOT_TESTED", "Web module disabled")
            capabilities["web_scan_quality"] = cap("web_scan_quality", "NOT_TESTED", "Web module disabled")
        capabilities["subdomain_discovery"] = cap("subdomain_discovery", "COMPLETED", None if subdomain_records else "No in-scope subdomains were discovered by CT/DNS/Nmap")
        capabilities["subdomain_assessment"] = cap("subdomain_assessment", module_states["subdomains"], "Discovered hosts require wildcard scope authorization when strict scope enforcement is enabled" if any(x.get("status") == "SKIPPED_SCOPE" for x in subdomain_scans) else None)
        if req.api:
            apis = module_states["api"]
            api_discovered = bool(api and getattr(api, "endpoints", []))
            capabilities["api_discovery"] = cap("api_discovery", apis, module_errors.get("api") if apis == "FAILED" else None)
            capabilities["openapi"] = cap("openapi", "COMPLETED" if api and getattr(api, "openapi", None) and getattr(api.openapi, "discovered", False) else "NOT_CONFIGURED", "OpenAPI specification not discovered" if not (api and getattr(api, "openapi", None) and getattr(api.openapi, "discovered", False)) else None)
            capabilities["rest_api"] = cap("rest_api", "COMPLETED" if api_discovered else "NOT_TESTED", "No API endpoints discovered" if not api_discovered else None)
            gql_discovered = bool(api and getattr(api, "graphql", None) and getattr(api.graphql, "discovered", False))
            capabilities["graphql"] = cap("graphql", "COMPLETED" if gql_discovered else "NOT_TESTED", None if gql_discovered else "No GraphQL endpoint discovered")
            auth_configured = bool(req.auth_header or req.cookie or (req.login_url and req.login_username and req.login_password))
            capabilities["authentication"] = cap("authentication", "COMPLETED" if auth_configured else "NOT_TESTED", "No authentication material configured" if not auth_configured else None)
            capabilities["authorization"] = cap("authorization", authorization_summary.get("status", "NOT_CONFIGURED"), authorization_summary.get("reason"))
            capabilities["rate_limiting"] = cap("rate_limiting", "COMPLETED" if api and getattr(api, "rate_limit_assessment", {}).get("status") not in {None, "NOT_TESTED", "FAILED"} else ("PARTIAL" if api else "NOT_TESTED"), None if api and getattr(api, "rate_limit_assessment", {}).get("status") not in {None, "NOT_TESTED", "FAILED"} else "Rate-limit signal is low-volume and absence of throttling is inconclusive")
            ws_list = getattr(api, "websockets", []) if api else []
            ws_tested = any(getattr(w, "handshake_attempted", False) for w in ws_list)
            capabilities["websocket"] = cap("websocket", "COMPLETED" if ws_tested else "NOT_TESTED", None if ws_tested else "No WebSocket endpoint candidates discovered in crawled HTML/JS")
            capabilities["vulnerability_verification"] = cap("vulnerability_verification", module_states["verification"])
        else:
            for name in ("api_discovery", "openapi", "rest_api", "graphql", "authentication", "authorization", "rate_limiting", "websocket"): capabilities[name] = cap(name, "NOT_TESTED", "API module disabled")
            capabilities["vulnerability_verification"] = cap("vulnerability_verification", "PARTIAL")
        # Assessment maturity stages. These are explicit capabilities rather
        # than optimistic labels: a stage is COMPLETED only when its evidence
        # exists in this scan snapshot.
        endpoint_count = int(assessment_intelligence.get("endpoint_count", 0))
        js_count = int(assessment_intelligence.get("assets_analyzed", 0) or assessment_intelligence.get("endpoint_count", 0))
        capabilities["endpoint_intelligence"] = cap("endpoint_intelligence", "COMPLETED" if endpoint_count else "PARTIAL", "No endpoints were inventoried" if not endpoint_count else None)
        capabilities["javascript_intelligence"] = cap("javascript_intelligence", "COMPLETED" if web and getattr(web, "javascript_assets", []) else ("NOT_TESTED" if not web else "PARTIAL"))
        source_intel = (getattr(web, "source_intelligence", {}) or {}) if web else {}
        source_status = source_intel.get("status", "NOT_TESTED") if isinstance(source_intel, dict) else "NOT_TESTED"
        capabilities["source_intelligence"] = cap("source_intelligence", source_status if source_status in {"COMPLETED","PARTIAL","FAILED","NOT_TESTED","DISABLED"} else "PARTIAL")
        if isinstance(source_intel, dict):
            for detector, payload in (source_intel.get("detectors") or {}).items():
                if detector == "correlated_secrets" or not isinstance(payload, dict):
                    continue
                state = payload.get("status", "NOT_TESTED")
                capabilities[f"source:{detector}"] = cap(f"source:{detector}", "NOT_TESTED" if state in {"DISABLED","NOT_INSTALLED"} else state, payload.get("reason"))
        capabilities["source_map_analysis"] = cap(
            "source_map_analysis",
            "COMPLETED" if source_intel.get("coverage", {}).get("source_maps", 0) else ("NOT_TESTED" if not web else "PARTIAL"),
        )
        capabilities["parameter_engine"] = cap("parameter_engine", "COMPLETED" if any(assessment_intelligence.get("parameter_class_counts", {}).values()) else ("PARTIAL" if endpoint_count else "NOT_TESTED"))
        capabilities["smart_test_selection"] = cap("smart_test_selection", "COMPLETED" if endpoint_count else "NOT_TESTED")
        capabilities["attack_chain_correlation"] = cap("attack_chain_correlation", "COMPLETED")
        capabilities["misconfiguration"] = cap("misconfiguration", "COMPLETED" if web or network else "NOT_TESTED")
        capabilities["secrets_detection"] = cap("secrets_detection", "COMPLETED" if web else "NOT_TESTED")
        capabilities["technology_aware_testing"] = cap("technology_aware_testing", "COMPLETED" if tech else "PARTIAL")
        for engine_name in EXTERNAL_ENGINE_NAMES:
            ext_state = external_scanners.get(engine_name, {}).get("status", "DISABLED")
            coverage_state = "NOT_TESTED" if ext_state in {"SKIPPED", "UNAVAILABLE", "DISABLED", "NOT_INSTALLED"} else ext_state
            capabilities[engine_name] = cap(engine_name, coverage_state, external_scanners.get(engine_name, {}).get("reason"))
        adv_state = advanced_security.get("status", "DISABLED") if isinstance(advanced_security, dict) else "DISABLED"
        capabilities["advanced_security"] = cap("advanced_security", adv_state, advanced_security.get("reason") if isinstance(advanced_security, dict) else None)
        if isinstance(advanced_security, dict):
            for adv_name, adv_status in (advanced_security.get("engines") or {}).items():
                capabilities[f"advanced:{adv_name}"] = cap(f"advanced:{adv_name}", adv_status, None)
        vals=[v["status"] for v in capabilities.values()]
        tested=sum(v=="COMPLETED" for v in vals); partial=sum(v=="PARTIAL" for v in vals); not_tested=sum(v=="NOT_TESTED" for v in vals); not_configured=sum(v=="NOT_CONFIGURED" for v in vals); failed_count=sum(v=="FAILED" for v in vals)
        denominator=len(vals); percentage=round((tested/denominator)*100,1) if denominator else 0.0
        web_login_succeeded = bool(getattr(getattr(web, "login_result", None), "succeeded", False)) if web else False
        auth_state = "authenticated" if req.auth_header or req.cookie or web_login_succeeded else "anonymous"
        normalized_target = self._normalize_target(req.target)
        limitations = []
        for name, state in module_states.items():
            if state in {"FAILED", "NOT_CONFIGURED", "DISABLED", "NOT_GENERATED", "PARTIAL"}: limitations.append(f"{name}: {state}" + (f" — {module_errors[name]}" if name in module_errors else ""))
        if web:
            for warning in (getattr(web, "scan_warnings", []) or []):
                if any(x in warning.lower() for x in ("challenge", "bot", "blocked", "forbidden", "captcha")):
                    limitations.append("Web application protection/challenge limited automated coverage: " + warning[:500])
        if not req.auth_header and not req.cookie and not web_login_succeeded: limitations.append("Authentication was not tested with operator credentials")
        if req.safe_mode == "safe":
            limitations.append("Safe mode: ZAP ran spider + passive analysis only (no active attack scan); POST forms and default-credential probes were skipped. Use Caution/Destructive on authorized targets for deeper coverage.")
        if web:
            for warning in (getattr(web, "scan_warnings", []) or []):
                if str(warning).startswith("ACTIVE_CHECKS_INCOMPLETE"):
                    limitations.append(str(warning)[:600])
        for engine_name in EXTERNAL_ENGINE_NAMES:
            _ext = external_scanners.get(engine_name) or {}
            if isinstance(_ext, dict) and _ext.get("auth_warning"):
                limitations.append(f"{engine_name.upper()}: {_ext['auth_warning']}")
        if authorization_summary.get("status") != "COMPLETED": limitations.append("Authorization differential testing was not completed; no two-identity authorized/unauthorized comparison was supplied")
        tls_support = getattr(getattr(web, "tls_info", None), "protocol_support", None) if web else None
        if tls_support and any(info.get("status") == "NOT_TESTED" and label in ("TLSv1", "TLSv1.1") for label, info in tls_support.items()):
            limitations.append("Legacy TLS protocol support (TLSv1/TLSv1.1) could not be conclusively verified — the scanning host's local TLS library refused to attempt the handshake, which does not necessarily mean the server itself rejects it")
        if any(x.get("status") == "SKIPPED_SCOPE" for x in subdomain_scans):
            limitations.append("Some discovered subdomains were not scanned because they were not explicitly authorized by the configured scope.")
        if not req.oob_callback_domain:
            limitations.append("Out-of-band (blind SSRF/XXE) testing was not performed — no oob_callback_domain was supplied")
        for engine_name in EXTERNAL_ENGINE_NAMES:
            ext_status = external_scanners.get(engine_name, {}).get("status")
            if ext_status in {"SKIPPED", "UNAVAILABLE", "NOT_CONFIGURED", "DISABLED", "NOT_INSTALLED", "NOT_TESTED"}:
                limitations.append(f"{engine_name.upper()} external engine was not executed: {ext_status}")
        if web:
            for detector, payload in ((getattr(web, "source_intelligence", {}) or {}).get("detectors") or {}).items():
                if detector == "correlated_secrets" or not isinstance(payload, dict):
                    continue
                state = payload.get("status")
                if state in {"DISABLED", "NOT_INSTALLED", "NOT_TESTED"}:
                    limitations.append(f"{detector.upper()} source detector was not executed: {state}")
        if isinstance(advanced_security, dict):
            for adv_name, adv_status in (advanced_security.get("engines") or {}).items():
                if adv_status in {"NOT_TESTED", "NOT_INSTALLED", "BUDGET_EXHAUSTED", "FAILED", "PARTIAL", "TIMEOUT"}:
                    limitations.append(f"Advanced engine {adv_name}: {adv_status}")
        if web and getattr(web, "oob_probes", None):
            limitations.append(f"{len(web.oob_probes)} out-of-band probe(s) were sent but not auto-confirmed — check your OOB provider's dashboard for interactions matching the correlation IDs listed under Assets/Evidence within this scan's time window")
        try:
            previous_findings, previous_scan_id = await history.previous_findings_for_target(normalized_target, exclude_scan_id=scan_id)
            scan_diff = compute_scan_diff(findings, previous_findings)
            if scan_diff is not None:
                scan_diff["compared_to_scan_id"] = previous_scan_id
        except Exception:
            # Trend tracking is a bonus on top of the scan, never a reason to
            # fail it — if the lookup fails for any reason, just omit it.
            scan_diff = None
        module_states["report"] = "PENDING"
        result = UnifiedScanResult(
            scan_id=scan_id,
            target=req.target,
            normalized_target=normalized_target,
            status=scan_status,
            started_at=started,
            finished_at=finished,
            network_scan=network,
            web_scan=web,
            api_scan=api,
            findings=findings,
            risk_score=bundle_score(findings),
            technologies=tech,
            assets=[asset, *subdomain_assets],
            subdomain_scans=subdomain_scans,
            warnings=warnings,
            dns=dns,
            subdomains=subdomain_records,
            tls=tls,
            javascript_intelligence=js,
            ai_validation=ai_validation,
            threat_intel=intel,
            assessment_intelligence=assessment_intelligence,
            external_scanners=external_scanners,
            canonical_artifacts=[{"artifact_id":aid,"engine":engine,"scan_id":scan_id,"execution_id":payload.get("execution_id")} for engine,payload in external_scanners.items() if isinstance(payload,dict) for aid in (payload.get("raw_artifact_ids") or [])],
            advanced_security=advanced_security,
            scan_diff=scan_diff,
            coverage={
                "network": network.coverage if network else {},
                "web": getattr(web, "coverage", {}) if web else {},
                "api": api.coverage if api else {},
                "capabilities": capabilities,
                "endpoint_matrix": build_endpoint_matrix(web, api),
                "tested": tested,
                "partial": partial,
                "not_tested": not_tested,
                "not_configured": not_configured,
                "failed": failed_count,
                "numerator": tested,
                "denominator": denominator,
                "percentage": percentage,
                "technologies": tech,
                "assets": len([a for a in [asset, *subdomain_assets] if a]),
            },
            limitations=limitations,
            compliance={},
            snapshot_metadata={"scan_id": scan_id, "target": req.target, "normalized_target": normalized_target, "scope": [normalized_target], "modules": requested, "authentication_state": auth_state, "configuration": {k: v for k, v in req.model_dump(mode="json").items() if k not in {"auth_header", "cookie", "authorized_auth_header", "authorized_cookie", "unauthorized_auth_header", "unauthorized_cookie", "login_url", "login_username", "login_password", "oob_callback_domain"}}, "created_at": started, "duration_seconds": (finished-started).total_seconds()},
            report_metadata={"report_id": f"rpt_{scan_id}", "generated_at": finished.isoformat(), "report_generator_version": "2.0"},
            pipeline={
                "states": module_states,
                "errors": module_errors,
                "requested": len(requested),
                "executed": len(completed),
                "modules_executed": f"{len(completed)}/{len(requested)}",
                "authorization": authorization_summary,
                "evidence_reconciliation": {
                    "status": "PARTIAL" if provenance_issues else "COMPLETED",
                    "external_engines": len(external_scanners),
                    "external_findings": sum(len((p or {}).get("findings") or []) for p in external_scanners.values() if isinstance(p, dict)),
                    "missing_artifact_links": len(provenance_issues),
                    "issues": provenance_issues[:100],
                    "confirmation": (verification_summary or {}).get("confirmation", {}),
                },
            },
            verification_summary=verification_summary,
            snapshot_version="2",
            scanner_version="1.0",
            ruleset_version="1.0",
            risk_engine_version="2.0",
        )

        try:
            if req.enable_finding_lifecycle:
                try:
                    from app.core.assessment_lifecycle import sync_scan_findings
                    lifecycle_items = await sync_scan_findings(result)
                    result.pipeline["finding_lifecycle"] = {"status":"COMPLETED","items":lifecycle_items}
                except Exception as exc:
                    result.pipeline["finding_lifecycle"] = {"status":"FAILED","error":str(exc)[:500]}
            result.pipeline["scan_profile"] = {"name":req.scan_profile,"safe_mode":req.safe_mode,"max_requests":req.max_requests,"requests_per_second":req.requests_per_second,"max_concurrency":req.max_concurrency}
            result.pipeline["assessment_policy"] = {
                "profile": req.scan_profile,
                "safe_mode": req.safe_mode,
                "write_methods_probed": req.probe_write_methods,
                "network": req.network,
                "web": req.web,
                "api": req.api,
                "subdomain_discovery": req.subdomain_discovery,
                "subdomain_dns_verification": req.subdomain_dns_verification,
                "subdomain_network_scan": req.subdomain_network_scan and req.network,
                "subdomain_web_scan": req.subdomain_web_scan and req.web,
                "subdomain_api_security": req.subdomain_api_security and req.api,
                "include_hardening_findings": req.include_hardening_findings,
                "request_budget": request_budget.snapshot(),
                "safety_policy": {"mode": req.safe_mode, "destructive_confirmation": req.destructive_confirmation},
            }
            await history.save(result)
            module_states["report"] = "COMPLETED"
            result.pipeline["report_persistence"] = {"status": "COMPLETED"}
            await history.save(result)
            try:
                from app.integrations.defectdojo.sync import enqueue_sync
                dd = await enqueue_sync(scan_id, tenant_context.get())
                result.pipeline.setdefault("defectdojo", {}).update(dd)
            except Exception as exc:
                result.pipeline.setdefault("defectdojo", {})["status"] = "FAILED"
                result.pipeline["defectdojo"]["error"] = f"{type(exc).__name__}"
        except Exception as exc:
            # A persistence failure must never turn a completed assessment into
            # a misleading 500. The scan result remains available to the caller;
            # the warning makes the missing history explicit.
            result.warnings.append(f"Scan completed but history persistence failed: {str(exc)[:500]}")
            result.pipeline.setdefault("persistence", {})["status"] = "FAILED"
            result.pipeline["persistence"]["error"] = str(exc)[:500]
            module_states["report"] = "PARTIAL"
            result.pipeline["report_persistence"] = {"status": "FAILED", "error": type(exc).__name__}
            if result.status == "completed":
                result.status = "partial"
        return result

    @staticmethod
    def _normalize_target(target: str) -> str:
        p = urlparse(target if "://" in target else "https://" + target)
        return f"{p.scheme}://{p.hostname}{f":{p.port}" if p.port else ""}" if p.hostname else target

    def compare(
        self,
        baseline: UnifiedScanResult,
        current: UnifiedScanResult,
    ):
        old = {
            f.finding_id: f
            for f in baseline.findings
        }

        new = {
            f.finding_id: f
            for f in current.findings
        }

        return ScanComparison(
            baseline_id=baseline.scan_id,
            current_id=current.scan_id,
            new_findings=[
                f
                for k, f in new.items()
                if k not in old
            ],
            fixed_finding_ids=[
                k
                for k in old
                if k not in new
            ],
            unchanged_finding_ids=[
                k
                for k in old
                if k in new
            ],
            severity_changes=[
                {
                    "finding_id": k,
                    "from": old[k].severity,
                    "to": new[k].severity,
                }
                for k in old.keys() & new.keys()
                if old[k].severity != new[k].severity
            ],
            score_delta=round(
                current.risk_score
                - baseline.risk_score,
                1,
            ),
        )


manager = ScanManager()
