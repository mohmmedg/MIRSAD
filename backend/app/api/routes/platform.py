from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
import asyncio
import re
import shutil
from pathlib import Path
from sqlalchemy import delete, exists, func, or_, select, union_all
from app.core.security import verify_api_key, require_analyst, require_scan_execution, require_viewer, require_admin
from app.core.config import settings
from app.core.rate_limit import limiter, scan_rate_limit
from app.core.architecture.manager import manager
from app.core.database import JobRow, ScanRow, session_scope, with_db_retry_async
from app.core.architecture.history import history
from app.core.scan_store import scan_store
from app.core.job_manager import job_manager
from app.core.worker_liveness import read_worker_heartbeat_status
from pydantic import BaseModel, Field
import httpx
from app.schemas.platform import FullScanRequest, UnifiedScanResult, ScanComparison
from app.modules.asset_inventory.inventory import inventory
from app.modules.reporting.generator import generate_markdown
from app.modules.reporting.exporters import to_html, to_sarif, to_json, to_csv, to_pdf
from app.core.auth_context import tenant_context
from app.core.auth import current_principal
from app.core.policy_enforcement import enforce_scan_admission, enforce_policy_rate_limit, scan_policy, scan_timeout_seconds

import logging as _logging
logger = _logging.getLogger(__name__)

router=APIRouter(prefix="/platform",tags=["platform"])

def _require_tenant_id() -> str:
    tid = tenant_context.get()
    if not tid:
        raise HTTPException(status_code=403, detail="Tenant context required")
    return tid

def _result_quality(result: dict | None) -> dict:
    """Deterministic quality/coverage audit for the raw persisted scan result.
    This never changes findings; it explains when a result deserves caution.
    """
    result = result or {}
    warnings = list(result.get("warnings") or [])
    web = result.get("web_scan") or {}
    checks = list(web.get("vulnerability_checks") or [])
    issues = []
    signals = []

    all_warnings = warnings + list(web.get("scan_warnings") or [])
    for w in all_warnings:
        lw = str(w).lower()
        if "circuit breaker" in lw or "stopped further active" in lw:
            issues.append({"code": "ACTIVE_TESTS_INTERRUPTED", "severity": "high", "message": str(w)})
        if any(x in lw for x in ("captcha", "challenge", "rate limit", "429", "waf")):
            issues.append({"code": "PROTECTION_OR_RATE_LIMIT", "severity": "medium", "message": str(w)})

    budget = web.get("request_budget") or {}
    used, maximum = budget.get("used"), budget.get("max_requests")
    if isinstance(used, (int, float)) and isinstance(maximum, (int, float)) and maximum > 0:
        signals.append({"code": "REQUEST_BUDGET", "used": used, "max": maximum, "utilization": round(used / maximum, 3)})

    static_re = re.compile(r"\.(?:css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot)(?:$|\?)", re.I)
    for f in checks:
        asset = str(f.get("url") or f.get("asset") or f.get("affected_asset") or "")
        name = str(f.get("check_name") or f.get("rule_id") or "").lower()
        evidence = str(f.get("evidence") or "")
        if static_re.search(asset) and any(x in name for x in ("ssti", "sqli", "time")):
            issues.append({"code": "STATIC_ASSET_ACTIVE_FINDING", "severity": "high",
                           "message": "Active injection finding points at a static asset; review required.", "asset": asset})
        if "49" in evidence and "7*7" in evidence:
            issues.append({"code": "LEGACY_SSTI_CANARY", "severity": "high",
                           "message": "Legacy SSTI canary {{7*7}}/49 detected; this result may come from a pre-fix worker."})
        if "sqli_time_blind" in name and str(f.get("confidence", "")).lower() == "low":
            signals.append({"code": "TIMING_FINDING_LOW_CONFIDENCE", "message": "Timing-based SQLi requires repeated verification."})
        if "ssti" in name and f.get("vulnerable") and "baseline" not in evidence.lower():
            issues.append({"code": "SSTI_NO_BASELINE_EVIDENCE", "severity": "medium",
                           "message": "SSTI positive lacks explicit baseline-differential evidence."})

    # Duplicate fingerprints/titles on the same asset are a quality signal, not
    # a vulnerability verdict.
    keys = [(str(f.get("title","")), str(f.get("affected_asset") or f.get("url") or "")) for f in result.get("findings") or []]
    dup = len(keys) - len(set(keys))
    if dup > 0:
        signals.append({"code": "DUPLICATE_FINDINGS", "count": dup})

    quality = "good"
    if any(i.get("severity") == "high" for i in issues):
        quality = "review_required"
    elif issues or any(s.get("code") == "TIMING_FINDING_LOW_CONFIDENCE" for s in signals):
        quality = "caution"
    return {"status": quality, "issues": issues[:100], "signals": signals[:100],
            "warning_count": len(all_warnings), "active_check_count": len(checks)}

async def _run_full_job(job, body):
    scan_store.mark_running(job.job_id)
    try:
        result = await manager.run(body, job=job)
        scan_store.mark_completed(job.job_id, result)
        return result
    except Exception as exc:
        scan_store.mark_failed(job.job_id, str(exc))
        raise

@router.post("/scan",response_model=UnifiedScanResult,dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def full_scan(request: Request, body: FullScanRequest):
    tenant_id = _require_tenant_id()
    await enforce_scan_admission(tenant_id)
    # max_scan_duration_minutes defaults to 0 = no time limit (see
    # policy_enforcement.scan_timeout_seconds). An admin can still opt into
    # a hard cap via policy settings, in which case this endpoint enforces
    # it the same way job_manager._execute/worker.py do.
    duration = scan_timeout_seconds(tenant_id)
    try:
        return await asyncio.wait_for(manager.run(body), timeout=duration)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail=f"تجاوز الفحص الحد الأقصى المسموح به ({int(duration) // 60} دقيقة) بسياسة الأمان. جرّب الفحص غير المتزامن (/platform/scan/async) للأهداف الكبيرة.",
        ) from exc

class TargetCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)

@router.post("/target-check", dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def target_check(body: TargetCheckRequest):
    """هل الهدف يعمل ويمكن الوصول إليه من حاويات الفحص؟ (للواجهة: زر «تحقق من الهدف» قبل بدء الفحص)."""
    from urllib.parse import urlparse
    from app.core.config import verify_target_in_scope, ScopeViolationError
    from app.modules.external_scanners.engines import probe_target_reachability
    try:
        host = urlparse(body.target).hostname or body.target
        verify_target_in_scope(host)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return await probe_target_reachability(body.target)

@router.post("/scan/async",status_code=202,dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def full_scan_async(request: Request, body: FullScanRequest, background_tasks: BackgroundTasks):
    await enforce_scan_admission(_require_tenant_id())
    job = await job_manager.create("full", body.target, lambda j: _run_full_job(j, body), start=False, payload=body.model_dump(mode="json"))
    scan_store.create("full", body.target, scan_id=job.job_id)
    runner=lambda j: _run_full_job(j, body)
    if settings.REDIS_URL and settings.JOB_QUEUE_ENABLED:
        job_manager.start(job, runner, payload=body.model_dump(mode="json"))
    else:
        background_tasks.add_task(job_manager.execute, job, runner)
    return {"scan_id": job.job_id, "job_id": job.job_id, "status": job.status.value}


@router.get("/scans/{scan_id}/artifacts/{artifact_id}", dependencies=[Depends(verify_api_key), Depends(require_analyst)])
async def read_raw_artifact(scan_id: str, artifact_id: str, raw: bool = False):
    tid=tenant_context.get()
    if not tid: raise HTTPException(status_code=403, detail="Tenant context required")
    from app.core.database import RawArtifactRow, AuditLogRow
    from app.core.raw_artifact_crypto import decrypt_artifact
    import re, uuid
    async with session_scope() as db:
        row=(await db.execute(select(RawArtifactRow).where(RawArtifactRow.artifact_id==artifact_id,RawArtifactRow.scan_id==scan_id,RawArtifactRow.tenant_id==tid))).scalar_one_or_none()
        if row is None: raise HTTPException(status_code=404,detail="Artifact not found")
        try: content=decrypt_artifact(bytes(row.content or b""))
        except Exception: raise HTTPException(status_code=500,detail="Artifact could not be decoded")
        text_content=content.decode("utf-8","replace")
        if not raw:
            text_content=re.sub(r"(?im)(authorization\s*:\s*bearer\s+)[^\s]+",r"\1[REDACTED]",text_content)
            text_content=re.sub(r"(?im)((?:cookie|password|passwd|secret|token|api[-_]?key)\s*[:=]\s*)[^\s,;]+",r"\1[REDACTED]",text_content)
        db.add(AuditLogRow(id="audit_"+uuid.uuid4().hex,tenant_id=tid,event="raw_artifact.read_raw" if raw else "raw_artifact.read_masked",target=scan_id,data={"artifact_id":artifact_id,"raw":raw},created_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc)))
        return {"artifact_id":row.artifact_id,"scan_id":row.scan_id,"tool":row.tool,"kind":row.kind,"sha256":row.sha256,"size_bytes":row.size_bytes,"encoding":row.encoding,"content":text_content}

def _select_reparse_artifacts(rows):
    """Select one complete evidence stream per supported parser/tool.

    Streaming scans persist both chunks and an aggregate. Parsing both creates
    duplicate findings; parsing stderr/report metadata creates false parser
    noise. Prefer complete structured output, then aggregate stdout, then the
    legacy non-streaming stdout artifact.
    """
    selected = []
    by_tool = {}
    for row in rows:
        by_tool.setdefault(str(row.tool or "").lower(), []).append(row)
    priorities = {
        "sqlmap": ("stdout_aggregate", "stdout"),
        "ghauri": ("stdout_aggregate", "stdout"),
        "nuclei": ("stdout_aggregate", "stdout"),
        "ffuf": ("output", "json", "stdout_aggregate", "stdout"),
    }
    for tool, kinds in priorities.items():
        candidates = by_tool.get(tool, [])
        for kind in kinds:
            matches = [row for row in candidates if row.kind == kind]
            if matches:
                selected.extend(matches)
                break
    return selected


@router.post("/scans/{scan_id}/reparse", dependencies=[Depends(verify_api_key), Depends(require_analyst)])
async def reparse_scan(scan_id: str):
    tid=tenant_context.get()
    if not tid: raise HTTPException(status_code=403,detail="Tenant context required")
    from app.core.database import RawArtifactRow, ScanRow, ReparseJobRow, ReparseResultRow
    from app.core.raw_artifact_crypto import decrypt_artifact
    from app.modules.external_scanners.engines import parse_sqlmap_output, parse_ghauri_output, parse_ffuf_json
    import json, uuid
    async with session_scope() as db:
        rows=(await db.execute(select(RawArtifactRow).where(RawArtifactRow.scan_id==scan_id,RawArtifactRow.tenant_id==tid).order_by(RawArtifactRow.created_at))).scalars().all()
        scan=(await db.execute(select(ScanRow).where(ScanRow.scan_id==scan_id,ScanRow.tenant_id==tid))).scalar_one_or_none()
        if scan is None: raise HTTPException(status_code=404,detail="Scan not found")
        parsed=[]
        for row in _select_reparse_artifacts(rows):
            raw=decrypt_artifact(bytes(row.content or b"")); text=raw.decode("utf-8","replace")
            if row.tool=="sqlmap":
                parsed.extend([{**x,"raw_artifact_id":row.artifact_id,"raw_locator":x.get("raw_locator")} for x in parse_sqlmap_output(text,scan.target)])
            elif row.tool=="ghauri":
                parsed.extend([{**x,"raw_artifact_id":row.artifact_id,"raw_locator":x.get("raw_locator")} for x in parse_ghauri_output(text,scan.target)])
            elif row.tool=="ffuf" and row.kind in {"json","output"}:
                try: parsed.extend([{**x,"raw_artifact_id":row.artifact_id} for x in parse_ffuf_json(json.loads(text))])
                except Exception as exc:
                    parsed.append({"parser_error":type(exc).__name__,"raw_artifact_id":row.artifact_id})
            elif row.tool=="nuclei":
                for i,line in enumerate(text.splitlines(),1):
                    try:
                        item=json.loads(line); info=item.get("info") or {}; parsed.append({"name":info.get("name") or item.get("template-id"),"template_id":item.get("template-id"),"severity":str(info.get("severity","Info")).title(),"matched_at":item.get("matched-at") or item.get("host"),"raw_artifact_id":row.artifact_id,"raw_locator":f"line:{i}"})
                    except Exception: continue
        if not rows:
            return {"scan_id":scan_id,"version":0,"reparse_job_id":None,"artifact_count":0,"finding_count":0,"findings":[]}
        result=dict(scan.result or {}); versions=list(result.get("reparse_versions") or []); version=len(versions)+1
        job_id="rpjob_"+uuid.uuid4().hex
        db.add(ReparseJobRow(reparse_job_id=job_id,tenant_id=tid,scan_id=scan_id,artifact_id=rows[0].artifact_id if rows else "",status="RUNNING",parser="canonical-external-parsers",result_version=version,created_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc)))
        for item in parsed:
            db.add(ReparseResultRow(reparse_result_id="rpr_"+uuid.uuid4().hex,tenant_id=tid,scan_id=scan_id,artifact_id=str(item.get("raw_artifact_id") or (rows[0].artifact_id if rows else "")),reparse_job_id=job_id,result_version=version,finding=item,created_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc)))
        versions.append({"version":version,"source":"raw_artifacts","artifact_ids":[r.artifact_id for r in rows],"findings":parsed,"reparse_job_id":job_id}); result["reparse_versions"]=versions; scan.result=result
        job_row=await db.get(ReparseJobRow,job_id)
        if job_row: job_row.status="COMPLETED"; job_row.finished_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc)
        return {"scan_id":scan_id,"version":version,"reparse_job_id":job_id,"artifact_count":len(rows),"finding_count":len(parsed),"findings":parsed}

@router.get("/scans/{scan_id}/report", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def download_report(scan_id: str, language: str = "ar", format: str = "pdf", audience: str = "technical"):
    """Export only the immutable, tenant-scoped finalized snapshot for scan_id.

    audience: 'technical' (default — full detail) or 'managerial'/'non_technical'
    (condensed: no raw evidence, finding IDs, or asset dumps).
    """
    import base64
    if audience not in ("technical", "managerial", "non_technical"):
        raise HTTPException(status_code=400, detail="audience must be technical, managerial, or non_technical")
    scan = await history.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan snapshot not found")
    if format == "markdown":
        return {"scan_id": scan_id, "format": "markdown", "audience": audience, "content": generate_markdown(scan, language, audience)}
    if format == "json":
        return {"scan_id": scan_id, "format": "json", "audience": audience, "content": to_json(scan, audience)}
    if format == "csv":
        return {"scan_id": scan_id, "format": "csv", "audience": audience, "content": to_csv(scan, audience)}
    if format == "html":
        return {"scan_id": scan_id, "format": "html", "audience": audience, "content": to_html(scan, language, audience)}
    if format == "sarif":
        if audience != "technical":
            raise HTTPException(status_code=400, detail="SARIF is available for technical reports only")
        return {"scan_id": scan_id, "format": "sarif", "audience": audience, "content": to_sarif(scan)}
    if format == "pdf":
        return {"scan_id": scan_id, "format": "pdf", "audience": audience, "content_base64": base64.b64encode(to_pdf(scan, language, audience)).decode("ascii")}
    raise HTTPException(status_code=400, detail="format must be pdf, markdown, json, csv, html, or sarif")


@router.get("/scans/{scan_id}/defectdojo", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def defectdojo_status(scan_id: str):
    tid=tenant_context.get()
    if not tid: raise HTTPException(status_code=403, detail="Tenant context required")
    from sqlalchemy import text
    from app.integrations.defectdojo.health import health
    async def q():
        async with session_scope() as db:
            rows=(await db.execute(text("select mapping_type,engagement_id,test_id,defectdojo_finding_id,fingerprint,idempotency_key from defectdojo_mappings where tenant_id=:t and scan_id=:s order by updated_at desc"),{"t":tid,"s":scan_id})).mappings().all()
            jobs=(await db.execute(text("select status,attempt_count,next_retry_at,last_error_code,last_error_message from external_sync_jobs where tenant_id=:t and scan_id=:s and provider='defectdojo' order by updated_at desc"),{"t":tid,"s":scan_id})).mappings().all()
            return [dict(r) for r in rows],[dict(j) for j in jobs]
    try: mappings,jobs=await with_db_retry_async(q)
    except Exception: mappings,jobs=[],[]
    return {"health":await health(),"mappings":mappings,"jobs":jobs}

@router.post("/scans/{scan_id}/defectdojo/resync", dependencies=[Depends(verify_api_key), Depends(require_admin)])
async def defectdojo_resync(scan_id: str):
    tid=tenant_context.get()
    if not tid: raise HTTPException(status_code=403, detail="Tenant context required")
    from app.integrations.defectdojo.sync import enqueue_sync
    return await enqueue_sync(scan_id,tid)

@router.post("/compare",response_model=ScanComparison,dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
@limiter.limit(scan_rate_limit())
async def compare(request: Request, baseline: UnifiedScanResult, current: UnifiedScanResult): return manager.compare(baseline,current)

@router.get("/tools/status", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def tool_status():
    """Return one authoritative runtime status for every scanner capability.

    The frontend must not infer a tool's state from a static sidebar list.
    Binary-backed tools are checked with PATH lookup, native engines are checked
    from their feature flag, and isolated services (ZAP/DefectDojo) are probed
    over the Docker network.
    """
    binary_specs = [
        ("nmap", "Nmap", "NMAP_BINARY_PATH", None),
        ("nuclei", "Nuclei", "NUCLEI_BINARY_PATH", None),
        ("sqlmap", "SQLMap", "SQLMAP_BINARY_PATH", None),
        ("ghauri", "Ghauri", "GHAURI_BINARY_PATH", None),
        ("ffuf", "FFUF", "FFUF_BINARY_PATH", None),
        ("testssl", "testssl.sh", "TESTSSL_BINARY_PATH", None),
        ("subfinder", "Subfinder", "SUBFINDER_BINARY_PATH", None),
        ("httpx", "ProjectDiscovery httpx", "HTTPX_BINARY_PATH", None),
        ("trivy", "Trivy", "TRIVY_BINARY_PATH", None),
        ("semgrep", "Semgrep", "SEMGREP_BINARY_PATH", None),
        ("gitleaks", "Gitleaks", "GITLEAKS_BINARY_PATH", None),
        ("trufflehog", "TruffleHog", "TRUFFLEHOG_BINARY_PATH", None),
    ]
    tools = []
    for key, label, path_setting, _ in binary_specs:
        binary = str(getattr(settings, path_setting, key))
        enabled_name = {
            "nmap": None, "nuclei": "ENABLE_NUCLEI", "sqlmap": "ENABLE_SQLMAP", "ghauri": "ENABLE_GHAURI",
            "ffuf": "ENABLE_FFUF", "testssl": "ENABLE_TESTSSL",
            "subfinder": "ENABLE_SUBFINDER", "httpx": "ENABLE_HTTPX_PROBE",
            "trivy": "ENABLE_TRIVY", "semgrep": "ENABLE_SEMGREP",
            "gitleaks": "ENABLE_GITLEAKS", "trufflehog": "ENABLE_TRUFFLEHOG",
        }.get(key)
        enabled = True if enabled_name is None else bool(getattr(settings, enabled_name, True))
        installed = shutil.which(binary) is not None
        tools.append({
            "key": key, "name": label, "kind": "binary",
            "enabled": enabled, "installed": installed,
            "status": "UP" if enabled and installed else "DOWN",
            "binary": binary,
        })

    # Native capabilities have no external binary to discover.
    for key, label in (
        ("network", "Network engine"),
        ("web", "Web crawler"),
        ("api", "API security"),
        ("source_intelligence", "Source intelligence"),
        ("source_map_analysis", "Source-map analysis"),
        ("playwright", "Playwright browser"),
        ("advanced_security", "Advanced security"),
    ):
        flag = "ENABLE_" + key.upper()
        enabled = True if key in {"network", "web", "api"} else bool(getattr(settings, flag, True))
        available = enabled
        if key == "playwright":
            browser_root = Path(getattr(settings, "PLAYWRIGHT_BROWSERS_PATH", "/opt/playwright-browsers"))
            available = enabled and browser_root.exists()
        tools.append({
            "key": key, "name": label, "kind": "native",
            "enabled": enabled, "installed": available,
            "status": "UP" if enabled and available else "DOWN",
        })

    # A queued scan cannot begin unless at least one Redis-stream worker is
    # alive. The worker writes an expiring heartbeat; this is intentionally a
    # health signal only and never alters scheduling or admission decisions.
    worker_up = False
    worker_count = 0
    heartbeat_age_seconds = None
    worker_status_reason = None
    if not settings.JOB_QUEUE_ENABLED:
        worker_status_reason = "Job queue is disabled"
    elif not settings.REDIS_URL:
        worker_status_reason = "REDIS_URL is not configured"
    else:
        try:
            import redis

            def _read_worker_heartbeats():
                heartbeat_client = redis.Redis.from_url(
                    settings.REDIS_URL, decode_responses=True,
                    socket_connect_timeout=1, socket_timeout=1,
                )
                try:
                    return read_worker_heartbeat_status(heartbeat_client, max_age_seconds=45)
                finally:
                    heartbeat_client.close()

            heartbeat_status = await asyncio.to_thread(_read_worker_heartbeats)
            worker_up = bool(heartbeat_status.get("up"))
            worker_count = int(heartbeat_status.get("worker_count") or 0)
            heartbeat_age_seconds = heartbeat_status.get("heartbeat_age_seconds")
            if not worker_up:
                worker_status_reason = "No fresh worker heartbeat in Redis (45-second freshness window)"
        except Exception:
            worker_up = False
            worker_status_reason = "Could not read worker heartbeat from Redis"
    tools.append({
        "key": "worker", "name": "Scan worker", "kind": "service",
        "enabled": bool(settings.JOB_QUEUE_ENABLED), "installed": worker_up,
        "status": "UP" if worker_up else "DOWN",
        "health": "AVAILABLE" if worker_up else "UNAVAILABLE",
        "worker_count": worker_count,
        "heartbeat_age_seconds": heartbeat_age_seconds,
        "status_reason": worker_status_reason,
    })

    async def probe(url: str, headers: dict | None = None) -> bool:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
                response = await client.get(url, headers=headers)
                return response.status_code < 500
        except Exception:
            return False

    zap_url = str(getattr(settings, "ZAP_SERVICE_URL", "") or "").rstrip("/")
    if zap_url:
        zap_headers = (
            {"X-ZAP-API-Key": settings.ZAP_API_KEY}
            if settings.ZAP_API_KEY
            else {}
        )
        zap_up = await probe(
            zap_url + "/JSON/core/view/version/",
            headers=zap_headers,
        )
    else:
        zap_up = False
    tools.append({
        "key": "zap", "name": "OWASP ZAP", "kind": "service",
        "enabled": bool(getattr(settings, "ENABLE_ZAP", True)),
        "installed": zap_up,
        "status": "UP" if getattr(settings, "ENABLE_ZAP", True) and zap_up else "DOWN",
        "url": zap_url,
    })

    from app.integrations.defectdojo.health import health as defectdojo_health
    dd_health = await defectdojo_health()
    dd_up = dd_health == "AVAILABLE"
    tools.append({
        "key": "defectdojo", "name": "DefectDojo", "kind": "service",
        "enabled": bool(getattr(settings, "DEFECTDOJO_ENABLED", True)),
        "installed": dd_up,
        "status": "UP" if getattr(settings, "DEFECTDOJO_ENABLED", True) and dd_up else "DOWN",
        "health": dd_health,
        "url": getattr(settings, "DEFECTDOJO_URL", "") or "",
    })
    return {"tools": tools, "all_defaults_enabled": True}


_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _valid_scan_id(scan_id: str) -> str:
    scan_id = (scan_id or "").strip()
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=422, detail="Invalid scan_id")
    return scan_id


async def _defectdojo_scan_engagement(client, scan_id: str) -> dict | None:
    """Return the DefectDojo engagement that holds ONE MIRSAD scan, or None if it
    has not been synced yet.

    The importer (integrations/defectdojo/retry.py) stores every scan as the
    engagement ``MIRSAD Scan <scan_id>`` inside the tenant's own product
    (``<prefix> / <tenant_id>``). Looking it up through that product keeps the
    lookup tenant-scoped: a caller can never reach another tenant's engagement
    by guessing a scan id.
    """
    tid = _require_tenant_id()
    product_name = f"{settings.DEFECTDOJO_PRODUCT_PREFIX} / {tid}"
    prods = await client.request("GET", "/api/v2/products/", params={"name": product_name, "limit": 20})
    product = next((p for p in (prods.get("results") or []) if p.get("name") == product_name), None)
    if not product:
        return None
    eng_name = f"MIRSAD Scan {scan_id}"
    engs = await client.request("GET", "/api/v2/engagements/", params={"product": product["id"], "name": eng_name, "limit": 20})
    return next((e for e in (engs.get("results") or []) if e.get("name") == eng_name), None)


@router.get("/defectdojo/dashboard", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def defectdojo_dashboard(scan_id: str | None = None):
    """Compact MIRSAD integration dashboard backed by the real DefectDojo API.

    With ``scan_id`` the counters describe only that scan's engagement instead of
    the whole DefectDojo instance.
    """
    from app.integrations.defectdojo.client import DefectDojoClient, DefectDojoError
    from app.integrations.defectdojo.health import health as defectdojo_health

    scan_id = _valid_scan_id(scan_id) if scan_id else None
    status = await defectdojo_health()
    base_url = (settings.DEFECTDOJO_URL or settings.DEFECTDOJO_API_URL or "").rstrip("/")
    payload = {
        "enabled": bool(settings.DEFECTDOJO_ENABLED),
        "health": status,
        "url": base_url,
        "products": 0,
        "engagements": 0,
        "tests": 0,
        "findings": 0,
        "findings_by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "scan_scope": None,
        "native_surfaces": [
            {"key":"dashboard","label":"Dashboard","path":"/"},
            {"key":"products","label":"Products / Applications","path":"/product"},
            {"key":"engagements","label":"Engagements","path":"/engagement"},
            {"key":"tests","label":"Tests","path":"/test"},
            {"key":"findings","label":"Findings","path":"/finding"},
            {"key":"reports","label":"Reports","path":"/report"},
            {"key":"metrics","label":"Metrics","path":"/metrics"},
            {"key":"users","label":"Users / Administration","path":"/user"},
            {"key":"api","label":"API v2 OpenAPI","path":"/api/v2/oa3/swagger-ui/"},
            {"key":"api_key","label":"API v2 Token","path":"/api/key-v2"},
        ],
        "error": None,
    }
    if status != "AVAILABLE":
        payload["error"] = status
        return payload

    client = DefectDojoClient()
    async def count(path: str, params: dict | None = None):
        data = await client.request("GET", path, params={**(params or {}), "limit": 1})
        return int(data.get("count") or 0)
    sev_names = ("Critical", "High", "Medium", "Low", "Info")
    try:
        if scan_id:
            eng = await _defectdojo_scan_engagement(client, scan_id)
            payload["scan_scope"] = {"scan_id": scan_id, "synced": bool(eng), "engagement_id": eng.get("id") if eng else None}
            if eng:
                eid = int(eng["id"])
                tests, findings, *sev_vals = await asyncio.gather(
                    count("/api/v2/tests/", {"engagement": eid}),
                    count("/api/v2/findings/", {"test__engagement": eid}),
                    *[count("/api/v2/findings/", {"test__engagement": eid, "severity": sv}) for sv in sev_names],
                )
                payload.update(products=1, engagements=1, tests=tests, findings=findings,
                               findings_by_severity=dict(zip(sev_names, sev_vals)))
            return payload
        products, engagements, tests, findings, *sev_vals = await asyncio.gather(
            count("/api/v2/products/"),
            count("/api/v2/engagements/"),
            count("/api/v2/tests/"),
            count("/api/v2/findings/"),
            *[count("/api/v2/findings/", {"severity": sv}) for sv in sev_names],
        )
        payload.update(products=products, engagements=engagements, tests=tests, findings=findings,
                       findings_by_severity=dict(zip(sev_names, sev_vals)))
    except DefectDojoError as exc:
        payload["error"] = exc.code
    return payload


@router.get("/defectdojo/findings", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def defectdojo_findings(limit: int = 50, offset: int = 0, severity: str | None = None,
                              q: str | None = None, active: bool | None = None,
                              product: int | None = None, order: str = "severity",
                              scan_id: str | None = None):
    """Findings actually stored in DefectDojo, resolved to product/engagement/test names,
    so the MIRSAD DefectDojo page can show the results themselves (not only counters)."""
    from app.integrations.defectdojo.client import DefectDojoClient, DefectDojoError
    from app.integrations.defectdojo.health import health as defectdojo_health

    take = max(1, min(int(limit), 200))
    skip = max(0, int(offset))
    scan_id = _valid_scan_id(scan_id) if scan_id else None
    out = {"enabled": bool(settings.DEFECTDOJO_ENABLED), "health": None, "total": 0,
           "limit": take, "offset": skip, "findings": [], "error": None, "scan_scope": None}
    status = await defectdojo_health()
    out["health"] = status
    if status != "AVAILABLE":
        out["error"] = status
        return out
    ordering = {"severity": "numerical_severity,-date", "newest": "-date", "oldest": "date"}.get(order, "numerical_severity,-date")
    params = {"limit": take, "offset": skip, "ordering": ordering}
    client = DefectDojoClient()
    if scan_id:
        # Scan scope: only the findings of that scan's engagement. A scan that has
        # not been pushed to DefectDojo yet is reported as `synced: False` (not as
        # an error) so the UI can say so instead of showing a misleading empty list.
        try:
            scan_eng = await _defectdojo_scan_engagement(client, scan_id)
        except DefectDojoError as exc:
            out["error"] = exc.code
            return out
        out["scan_scope"] = {"scan_id": scan_id, "synced": bool(scan_eng), "engagement_id": scan_eng.get("id") if scan_eng else None}
        if not scan_eng:
            out["products"] = []
            return out
        params["test__engagement"] = int(scan_eng["id"])
    elif product is not None:
        params["test__engagement__product"] = int(product)
    if severity and severity.capitalize() in ("Critical", "High", "Medium", "Low", "Info"):
        params["severity"] = severity.capitalize()
    if q and q.strip():
        params["title"] = q.strip()
    if active is not None:
        params["active"] = "true" if active else "false"
    try:
        page, tests, engagements, products = await asyncio.gather(
            client.request("GET", "/api/v2/findings/", params=params),
            client.request("GET", "/api/v2/tests/", params={"limit": 1000}),
            client.request("GET", "/api/v2/engagements/", params={"limit": 1000}),
            client.request("GET", "/api/v2/products/", params={"limit": 1000}),
        )
    except DefectDojoError as exc:
        out["error"] = exc.code
        return out
    prod_name = {p.get("id"): p.get("name") for p in products.get("results", [])}
    eng = {e.get("id"): e for e in engagements.get("results", [])}
    test = {t.get("id"): t for t in tests.get("results", [])}
    items = []
    for f in page.get("results", []):
        t = test.get(f.get("test")) or {}
        e = eng.get(t.get("engagement")) or {}
        vids = [v.get("vulnerability_id") for v in (f.get("vulnerability_ids") or []) if isinstance(v, dict)]
        items.append({
            "id": f.get("id"), "title": f.get("title"), "severity": f.get("severity"),
            "date": f.get("date"), "active": f.get("active"), "verified": f.get("verified"),
            "false_p": f.get("false_p"), "duplicate": f.get("duplicate"),
            "risk_accepted": f.get("risk_accepted"), "mitigated": f.get("mitigated"),
            "cwe": f.get("cwe") or None, "cve": (vids[0] if vids else None),
            "component": f.get("component_name") or f.get("file_path") or None,
            "test": t.get("title") or t.get("test_type_name"),
            "engagement": e.get("name"), "product": prod_name.get(e.get("product")),
            "product_id": e.get("product"),
        })
    out["total"] = int(page.get("count") or 0)
    out["findings"] = items
    out["products"] = [{"id": k, "name": v} for k, v in sorted(prod_name.items(), key=lambda kv: str(kv[1]).lower())]
    return out


@router.get("/defectdojo/findings/{finding_id}", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def defectdojo_finding_detail(finding_id: int):
    """Full text of one DefectDojo finding for the detail drawer."""
    from app.integrations.defectdojo.client import DefectDojoClient, DefectDojoError

    try:
        f = await DefectDojoClient().request("GET", f"/api/v2/findings/{int(finding_id)}/")
    except DefectDojoError as exc:
        if exc.code == "NOT_FOUND":
            raise HTTPException(status_code=404, detail="Finding not found")
        raise HTTPException(status_code=502, detail=exc.code)
    vids = [v.get("vulnerability_id") for v in (f.get("vulnerability_ids") or []) if isinstance(v, dict)]
    def txt(key, cap=20000):
        v = f.get(key)
        return v[:cap] if isinstance(v, str) and v.strip() else None
    return {
        "id": f.get("id"), "title": f.get("title"), "severity": f.get("severity"),
        "description": txt("description"), "mitigation": txt("mitigation"), "impact": txt("impact"),
        "references": txt("references"), "steps_to_reproduce": txt("steps_to_reproduce"),
        "cvss_score": f.get("cvssv3_score"), "cvss_vector": f.get("cvssv3"),
        "epss_score": f.get("epss_score"), "cwe": f.get("cwe") or None, "cve_ids": [v for v in vids if v],
        "file_path": f.get("file_path") or None, "line": f.get("line") or None,
        "component": f.get("component_name") or None, "component_version": f.get("component_version") or None,
        "date": f.get("date"), "age_days": f.get("age"), "sla_days_remaining": f.get("sla_days_remaining"),
        "active": f.get("active"), "verified": f.get("verified"),
        "tags": f.get("tags") if isinstance(f.get("tags"), list) else [],
    }


@router.get("/assets",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def assets(): return {"assets": await inventory.list()}

@router.get("/history",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def history_list(limit: int = 50): return {"scans": await history.list(max(1,min(limit,200)))}

@router.get("/scan-history",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def scan_history_list(limit: int = 50, offset: int = 0, q: str | None = None, status: str | None = None):
    """Return the complete durable scan history for the current tenant.

    ``scans`` is the canonical history table. Legacy ``scan_jobs`` rows are
    included when an older deployment has a job without a matching scan row.
    Pagination controls transfer size only; it is not a retention/quota limit.
    """
    tid = tenant_context.get() or "legacy"
    principal = current_principal()
    owner_user_id = principal.user_id
    take = max(1, min(int(limit), 200))
    skip = max(0, int(offset))

    async def _query():
        async with session_scope(tid) as db:
            # Canonical persisted history.
            scan_q = select(
                ScanRow.scan_id.label("scan_id"), ScanRow.job_id.label("job_id"),
                ScanRow.target.label("target"), ScanRow.scan_kind.label("scan_kind"),
                ScanRow.status.label("status"), ScanRow.created_at.label("created_at"),
                ScanRow.finished_at.label("finished_at"), ScanRow.result.label("result"),
                ScanRow.error_message.label("error_message"),
            ).where(ScanRow.tenant_id == tid, ScanRow.created_by_user_id == owner_user_id)

            # Backfill visibility for jobs created before the durable ScanRow
            # history record was introduced.
            legacy_job_q = select(
                JobRow.job_id.label("scan_id"), JobRow.job_id.label("job_id"),
                JobRow.target.label("target"), JobRow.job_type.label("scan_kind"),
                JobRow.status.label("status"), JobRow.created_at.label("created_at"),
                JobRow.finished_at.label("finished_at"), JobRow.result.label("result"),
                JobRow.error_message.label("error_message"),
            ).where(
                JobRow.tenant_id == tid,
                JobRow.created_by_user_id == owner_user_id,
                ~exists(select(1).where(ScanRow.tenant_id == tid, ScanRow.scan_id == JobRow.job_id)),
            )

            combined = union_all(scan_q, legacy_job_q).subquery("scan_history")
            base = select(combined)
            if q and q.strip():
                term = f"%{q.strip()}%"
                base = base.where(or_(combined.c.target.ilike(term), combined.c.scan_id.ilike(term)))
            if status and status.lower() != "all":
                base = base.where(combined.c.status == status.lower())
            total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
            rows = (await db.execute(base.order_by(combined.c.created_at.desc()).offset(skip).limit(take))).mappings().all()
            return total, rows

    # A transient Supabase/Postgres disconnect ("SSL SYSCALL error: EOF
    # detected") used to surface as a bare 500 with zero retries — see
    # with_db_retry_async's docstring in app/core/database.py for why
    # pool_pre_ping alone cannot catch a connection that dies mid-query.
    # 2026-09-16: was routed through run_db()/run_in_threadpool (sync
    # SQLAlchemy on a background thread); now natively async end-to-end via
    # asyncpg, so this await runs directly on the event loop without
    # blocking any other concurrent request.
    total, rows = await with_db_retry_async(_query)

    items = []
    for row in rows:
        result = row.get("result") if isinstance(row.get("result"), dict) else None
        findings = (result or {}).get("findings") or []
        risk = (result or {}).get("risk_score")
        items.append({
            "scan_id": row.get("scan_id"), "job_id": row.get("job_id"), "target": row.get("target"),
            "scan_kind": row.get("scan_kind"), "status": row.get("status"),
            "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            "started_at": (result or {}).get("started_at") or (row.get("created_at").isoformat() if row.get("created_at") else None),
            "finished_at": row.get("finished_at").isoformat() if row.get("finished_at") else None,
            "risk_score": float(risk) if risk is not None else None,
            "findings_count": len(findings), "result": result,
            "result_quality": _result_quality(result),
            "error_message": row.get("error_message"),
        })
    return {"scans": items, "total": int(total), "offset": skip, "limit": take}

_ACTIVE_STATUSES = {"pending", "running", "paused", "cancel_requested"}


@router.delete("/scan-history/{scan_id}", dependencies=[Depends(verify_api_key), Depends(require_analyst)])
async def delete_scan_history(scan_id: str):
    """Permanently delete one of the caller's own scans and everything stored for it.

    Refuses scans that are still active (cancel them first). Tables without a
    cascading FK to ``scans`` are deleted explicitly; the rest (executions, trace
    events, engine results, findings sources, raw artifacts, DefectDojo mappings,
    lifecycle, ...) cascade from the ``scans`` row.
    """
    from sqlalchemy import text
    tid = tenant_context.get() or "legacy"
    owner = current_principal().user_id

    async def _delete():
        async with session_scope(tid) as db:
            rows = (await db.execute(text(
                "select status from scans where scan_id=:s and tenant_id=:t and created_by_user_id is not distinct from :o "
                "union all select status from scan_jobs where job_id=:s and tenant_id=:t and created_by_user_id is not distinct from :o"),
                {"s": scan_id, "t": tid, "o": owner})).scalars().all()
            if not rows:
                raise HTTPException(status_code=404, detail="Scan not found")
            if any(str(r) in _ACTIVE_STATUSES for r in rows):
                raise HTTPException(status_code=409, detail="Scan is still active; cancel it before deleting")
            p = {"s": scan_id, "t": tid}
            for stmt in (
                "delete from scan_execution_events where scan_id=:s and tenant_id=:t",
                "delete from scan_executions where scan_id=:s and tenant_id=:t",
                "delete from verification_attempts where scan_id=:s and tenant_id=:t",
                "delete from bas_replay_runs where scan_id=:s and tenant_id=:t",
                "delete from scan_snapshots where scan_id=:s and tenant_id=:t",
                "delete from scan_jobs where tenant_id=:t and (job_id=:s or job_id in (select job_id from scans where scan_id=:s and tenant_id=:t))",
                "delete from scans where scan_id=:s and tenant_id=:t",  # cascades the remaining child tables
            ):
                await db.execute(text(stmt), p)
    await with_db_retry_async(_delete)
    try:  # drop the Redis hot snapshot too (best-effort)
        from app.core.job_manager import _hot_cache, _hot_key
        r = _hot_cache()
        if r is not None:
            await asyncio.to_thread(r.delete, _hot_key(tid, scan_id))
    except Exception:
        logger.debug("suppressed non-fatal error", exc_info=True)
    return {"deleted": scan_id}

@router.get("/history/{scan_id}",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def history_get(scan_id: str):
    item=await history.get(scan_id)
    if item is None: raise HTTPException(status_code=404,detail="Scan not found")
    return item

@router.post("/compare-history",response_model=ScanComparison,dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def compare_history(baseline_id: str, current_id: str):
    baseline=await history.get(baseline_id); current=await history.get(current_id)
    if not baseline or not current: raise HTTPException(status_code=404,detail="Baseline or current scan not found")
    return manager.compare(baseline,current)

@router.get("/organization-score",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def organization_score(limit: int = 200):
    """2.3: MIRSAD Score - organization-wide weighted risk aggregate across
    the tenant's most recently completed scan of each distinct target.

    Pulls from history.list() (the same finalized-snapshot source /platform/history
    uses) rather than the live in-memory scan_store, so the score reflects
    durable, persisted results and survives restarts. `limit` bounds how many
    recent snapshots are scanned to build the per-target set - raise it if a
    tenant has more than ~200 distinct targets and some are being missed.
    """
    from app.modules.risk_engine.engine import organization_score as _compute
    # Same transient-disconnect retry as /scan-history above — this endpoint
    # was the other one seen bare-500ing on a single SSL EOF against Supabase.
    # 2026-09-16: natively async now (asyncpg), no run_db/threadpool needed.
    snapshots = await with_db_retry_async(lambda: history.list(max(1, min(limit, 500))))
    latest_by_target: dict[str, dict] = {}
    for snap in snapshots:  # already newest-first
        target = (snap or {}).get("target")
        if target and target not in latest_by_target:
            latest_by_target[target] = snap
    return _compute(list(latest_by_target.values()))


class WhatIfRequest(BaseModel):
    """Advisory planning input: which findings a user is considering fixing."""
    finding_ids: list[str] = Field(default_factory=list)
    limit: int = 200


@router.post("/what-if", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def what_if_remediation(body: WhatIfRequest):
    """Bet 2 (agentic-AI layer): 'if we fixed these findings, how much would
    the MIRSAD Score drop?' - a pure read-only projection over the same
    snapshot set /organization-score uses. Never marks anything as fixed;
    it only recomputes the deterministic score formula with the named
    finding_ids excluded, so a security team can prioritize before doing
    any real remediation work.
    """
    from app.modules.risk_engine.engine import simulate_fix_impact
    # Same with_db_retry_async offload as /organization-score above.
    snapshots = await with_db_retry_async(lambda: history.list(max(1, min(body.limit, 500))))
    latest_by_target: dict[str, dict] = {}
    for snap in snapshots:
        target = (snap or {}).get("target")
        if target and target not in latest_by_target:
            latest_by_target[target] = snap
    return simulate_fix_impact(list(latest_by_target.values()), body.finding_ids)


