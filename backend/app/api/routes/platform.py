from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from app.core.security import verify_api_key, require_analyst, require_viewer
from app.core.config import settings
from app.core.rate_limit import limiter, scan_rate_limit
from app.core.architecture.manager import manager
from app.core.architecture.history import history
from app.core.scan_store import scan_store
from app.core.job_manager import job_manager
from app.schemas.platform import FullScanRequest, UnifiedScanResult, ScanComparison
from app.modules.asset_inventory.inventory import inventory
from app.modules.reporting.generator import generate_markdown
from app.modules.reporting.exporters import to_html, to_sarif, to_json, to_csv, to_pdf
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import scan_policy, scan_slot, enforce_policy_rate_limit

router=APIRouter(prefix="/platform",tags=["platform"])

async def _run_full_job(job, body):
    scan_store.mark_running(job.job_id)
    try:
        result = await manager.run(body, job=job)
        scan_store.mark_completed(job.job_id, result)
        return result
    except Exception as exc:
        scan_store.mark_failed(job.job_id, str(exc))
        raise

@router.post("/scan",response_model=UnifiedScanResult,dependencies=[Depends(verify_api_key), Depends(require_analyst)])
@limiter.limit(scan_rate_limit())
async def full_scan(request: Request, body: FullScanRequest):
    tenant_id=tenant_context.get() or "legacy"; policy=scan_policy(tenant_id)
    await enforce_policy_rate_limit("scan", tenant_id, int(policy["rate_limit_per_minute"]))
    try:
        async with scan_slot(tenant_id):
            return await __import__("asyncio").wait_for(manager.run(body), timeout=int(policy["max_scan_duration_minutes"])*60)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc

@router.post("/scan/async",status_code=202,dependencies=[Depends(verify_api_key), Depends(require_analyst)])
@limiter.limit(scan_rate_limit())
async def full_scan_async(request: Request, body: FullScanRequest, background_tasks: BackgroundTasks):
    job = await job_manager.create("full", body.target, lambda j: _run_full_job(j, body), start=False, payload=body.model_dump(mode="json"))
    scan_store.create("full", body.target, scan_id=job.job_id)
    runner=lambda j: _run_full_job(j, body)
    if settings.REDIS_URL and settings.JOB_QUEUE_ENABLED:
        job_manager.start(job, runner, payload=body.model_dump(mode="json"))
    else:
        background_tasks.add_task(job_manager.execute, job, runner)
    return {"scan_id": job.job_id, "job_id": job.job_id, "status": job.status.value}

@router.post("/report",dependencies=[Depends(verify_api_key), Depends(require_analyst)])
async def report(request: Request, body: UnifiedScanResult, language: str="ar", format: str="markdown"):
    if format=="markdown": return {"format":"markdown","content":generate_markdown(body,language)}
    if format=="html": return {"format":"html","content":to_html(body,language)}
    if format=="sarif": return {"format":"sarif","content":to_sarif(body)}
    if format=="json": return {"format":"json","content":to_json(body)}
    if format=="csv": return {"format":"csv","content":to_csv(body)}
    if format=="pdf": return {"format":"pdf","content_base64":__import__("base64").b64encode(to_pdf(body,language)).decode("ascii")}
    raise HTTPException(status_code=400,detail="format must be markdown, html, json, csv, pdf, or sarif")

@router.post("/compare",response_model=ScanComparison,dependencies=[Depends(verify_api_key), Depends(require_analyst)])
@limiter.limit(scan_rate_limit())
async def compare(request: Request, baseline: UnifiedScanResult, current: UnifiedScanResult): return manager.compare(baseline,current)

@router.get("/assets",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def assets(): return {"assets":inventory.list()}

@router.get("/history",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def history_list(limit: int = 50): return {"scans": history.list(max(1,min(limit,200)))}

@router.get("/history/{scan_id}",dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def history_get(scan_id: str):
    item=history.get(scan_id)
    if item is None: raise HTTPException(status_code=404,detail="Scan not found")
    return item

@router.post("/compare-history",response_model=ScanComparison,dependencies=[Depends(verify_api_key), Depends(require_analyst)])
async def compare_history(baseline_id: str, current_id: str):
    baseline=history.get(baseline_id); current=history.get(current_id)
    if not baseline or not current: raise HTTPException(status_code=404,detail="Baseline or current scan not found")
    return manager.compare(baseline,current)
