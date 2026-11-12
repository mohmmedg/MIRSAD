"""
api/routes/network.py

Endpoints:
- POST /api/v1/network/scan          — تنفيذ متزامن (ينتظر النتيجة الكاملة)
- POST /api/v1/network/scan/async    — يبدأ الفحص كـ background task ويرجع
  scan_id فوراً (202 Accepted)؛ تابع الحالة عبر GET /api/v1/scans/{scan_id}/status

قرار تصميم متعمّد: أبقينا endpoint المتزامن كما هو (بدل حذفه بالكامل) لأن
فحوصات basic السريعة ما تحتاج تعقيد background task إضافي، وحذفه كان
بيكسر أي عميل موجود يعتمد عليه. الإضافة الجديدة (/scan/async) هي الحل
لمشكلة full scan الطويلة (دقايق) المذكورة بالـ README كخطوة تالية —
الآن العميل يقدر يبدأ الفحص، يكمل يستخدم الواجهة، ويتابع الحالة عبر polling.
"""

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

from app.modules.network_scan.scanner import NetworkScanner, SCAN_PROFILES
from app.schemas.network import NetworkScanResult

router = APIRouter(prefix="/network", tags=["network"])
scanner = NetworkScanner()


class NetworkScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    ports: str | None = None
    timing: int | None = None


class AsyncScanAccepted(BaseModel):
    scan_id: str
    status: str = "pending"


async def _raise_for_scope_or_ssrf(
    target: str, scan_type: str | None, client_host: str | None
) -> None:
    """يتحقق من scope/SSRF ويرفع HTTPException المناسب مع تسجيل audit log —
    مشترك بين المسار المتزامن وغير المتزامن عشان نفشل بسرعة (fail-fast)
    قبل حتى إنشاء سجل الفحص، بدل ما نرجع 202 لهدف مرفوض أصلاً."""
    try:
        verify_target_in_scope(target)
    except SSRFRiskError as exc:
        await log_scan_request(
            scan_kind="network",
            target=target,
            scan_type=scan_type,
            scope_check_result="ssrf_blocked",
            client_host=client_host,
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ScopeViolationError as exc:
        await log_scan_request(
            scan_kind="network",
            target=target,
            scan_type=scan_type,
            scope_check_result="scope_violation",
            client_host=client_host,
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/scan", response_model=NetworkScanResult, dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def run_network_scan(request: Request, body: NetworkScanRequest) -> NetworkScanResult:
    client_host = request.client.host if request.client else None
    await _raise_for_scope_or_ssrf(body.target, body.scan_type, client_host)
    await enforce_scan_admission(tenant_context.get() or "legacy")
    try:
        result = await scanner.scan(target=body.target, scan_type=body.scan_type, ports=body.ports, timing=body.timing)
        await log_scan_request(scan_kind="network", target=body.target, scan_type=body.scan_type, scope_check_result="allowed", client_host=client_host)
        if tenant_context.get():
            await correlate_and_escalate(tenant_id=tenant_context.get(), result=result, run_gemini=bool(settings.GEMINI_API_KEY))
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _run_network_scan_background(scan_id: str, target: str, scan_type: str) -> None:
    scan_store.mark_running(scan_id)
    try:
        result = await scanner.scan(target=target, scan_type=scan_type)
        scan_store.mark_completed(scan_id, result)
        await log_scan_request(
            scan_kind="network", target=target, scan_type=scan_type, scope_check_result="allowed"
        )
    except Exception as exc:  # noqa: BLE001 — نلتقط أي فشل غير متوقع بالفحص
        # حماية إضافية بمستوى background task: scope/SSRF اتفحصوا سلفاً
        # بـ _raise_for_scope_or_ssrf قبل جدولة المهمة، لكن أي فشل آخر
        # (nmap غير موجود، timeout، إلخ) يجب أن يُسجَّل بحالة failed بدل
        # ما يختفي بصمت (background task ما إله caller ينتظر الاستثناء)
        scan_store.mark_failed(scan_id, str(exc))


@router.post("/scan/async", response_model=AsyncScanAccepted, status_code=202, dependencies=[Depends(verify_api_key), Depends(require_scan_execution)])
async def run_network_scan_async(request: Request, body: NetworkScanRequest, background_tasks: BackgroundTasks) -> AsyncScanAccepted:
    client_host=request.client.host if request.client else None
    if body.scan_type not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail=f"scan_type غير معروف: '{body.scan_type}'")
    await _raise_for_scope_or_ssrf(body.target, body.scan_type, client_host)
    await enforce_scan_admission(tenant_context.get() or "legacy")
    payload=body.model_dump(mode="json")
    job=await job_manager.create("network",body.target,start=False,payload=payload)
    async def runner(j):
        await j.checkpoint("network"); return await scanner.scan(target=body.target,scan_type=body.scan_type,ports=body.ports,timing=body.timing)
    if settings.REDIS_URL and settings.JOB_QUEUE_ENABLED:
        job_manager.start(job,runner,payload=payload)
    else:
        background_tasks.add_task(job_manager.execute,job,runner)
    return AsyncScanAccepted(scan_id=job.job_id,status=job.status.value)

