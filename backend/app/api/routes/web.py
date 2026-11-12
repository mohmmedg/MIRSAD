"""
api/routes/web.py

Endpoints:
- POST /api/v1/web/scan          — تنفيذ متزامن
- POST /api/v1/web/scan/async    — background task + متابعة عبر
  GET /api/v1/scans/{scan_id}/status (راجع نفس القرار الموثّق بـ network.py)
"""

import urllib.parse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.audit_log import log_scan_request
from app.core.config import ScopeViolationError, SSRFRiskError, verify_target_in_scope
from app.core.rate_limit import limiter
from app.core.scan_store import scan_store
from app.core.job_manager import job_manager
from app.core.finding_pipeline import correlate_and_escalate
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import enforce_scan_admission
from app.core.security import verify_api_key, require_analyst, require_scan_execution
from app.core.config import settings

from app.modules.web_scan.scanner import WebScanner
from app.schemas.web import WebScanResult

router = APIRouter(prefix="/web", tags=["web"])
scanner = WebScanner()


class WebScanRequest(BaseModel):
    target: str
    profile: str = "balanced"
    max_pages: int | None = None
    max_depth: int | None = None


class AsyncScanAccepted(BaseModel):
    scan_id: str
    status: str = "pending"


async def _raise_for_scope_or_ssrf(target: str, client_host: str | None) -> None:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        # رابط غير صالح أصلاً — نترك رسالة الخطأ الواضحة لـ WebScanner.scan()
        # (ValueError -> 400) بدل ما نصنّفه غلط كـ scope violation (403)
        return
    hostname = parsed.hostname
    try:
        verify_target_in_scope(hostname)
    except SSRFRiskError as exc:
        await log_scan_request(
            scan_kind="web", target=target, scope_check_result="ssrf_blocked", client_host=client_host
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ScopeViolationError as exc:
        await log_scan_request(
            scan_kind="web", target=target, scope_check_result="scope_violation", client_host=client_host
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/scan", response_model=WebScanResult, dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def run_web_scan(request: Request, body: WebScanRequest) -> WebScanResult:
    client_host = request.client.host if request.client else None
    await _raise_for_scope_or_ssrf(body.target, client_host)
    await enforce_scan_admission(tenant_context.get() or "legacy")
    try:
        result = await scanner.scan(target_url=body.target, profile=body.profile, max_pages=body.max_pages, max_depth=body.max_depth)
        await log_scan_request(scan_kind="web", target=body.target, scope_check_result="allowed", client_host=client_host)
        if tenant_context.get():
            await correlate_and_escalate(tenant_id=tenant_context.get(), result=result, run_gemini=bool(settings.GEMINI_API_KEY))
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _run_web_scan_background(scan_id: str, target: str) -> None:
    scan_store.mark_running(scan_id)
    try:
        result = await scanner.scan(target_url=target, profile="balanced")
        scan_store.mark_completed(scan_id, result)
        await log_scan_request(scan_kind="web", target=target, scope_check_result="allowed")
    except Exception as exc:  # noqa: BLE001
        scan_store.mark_failed(scan_id, str(exc))


@router.post("/scan/async", response_model=AsyncScanAccepted, status_code=202, dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def run_web_scan_async(request: Request, body: WebScanRequest, background_tasks: BackgroundTasks) -> AsyncScanAccepted:
    client_host=request.client.host if request.client else None
    if not urllib.parse.urlparse(body.target).hostname:
        raise HTTPException(status_code=400, detail=f"URL غير صالح: '{body.target}'")
    await _raise_for_scope_or_ssrf(body.target, client_host)
    await enforce_scan_admission(tenant_context.get() or "legacy")
    payload=body.model_dump(mode="json")
    job=await job_manager.create("web",body.target,start=False,payload=payload)
    job_tenant_id = tenant_context.get() or "legacy"
    async def runner(j):
        # BackgroundTasks do not reliably preserve request ContextVars. Re-enter
        # the tenant context captured at job creation so scanner policy, findings,
        # and persistence remain attached to the same tenant/scan lineage.
        token = tenant_context.set(job_tenant_id)
        try:
            await j.checkpoint("web")
            return await scanner.scan(target_url=body.target,profile=body.profile,max_pages=body.max_pages,max_depth=body.max_depth)
        finally:
            tenant_context.reset(token)
    if settings.REDIS_URL and settings.JOB_QUEUE_ENABLED:
        job_manager.start(job,runner,payload=payload)
    else:
        background_tasks.add_task(job_manager.execute,job,runner)
    return AsyncScanAccepted(scan_id=job.job_id,status=job.status.value)

