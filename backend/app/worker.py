"""Durable Redis worker for scan jobs.
Run inside the worker container: WORKER_MODE=true python -m app.worker
"""
from __future__ import annotations
import asyncio
import redis
from app.core.config import settings
from app.core.database import JobRow, session_scope, utcnow
from app.core.auth_context import tenant_context
from app.core.job_manager import JobRecord
from app.core.finding_pipeline import correlate_and_escalate
from app.core.architecture.manager import manager
from app.modules.network_scan.scanner import NetworkScanner
from app.modules.web_scan.scanner import WebScanner
from app.schemas.jobs import JobStatus
from app.schemas.platform import FullScanRequest
from app.modules.continuous import ContinuousScanner, CONTINUOUS_QUEUE, ENQUEUE_LOCK_PREFIX
import os, socket, uuid, json

network_scanner=NetworkScanner(); web_scanner=WebScanner()

async def run_job(job_id: str):
    with session_scope() as db:
        row=db.get(JobRow,job_id)
        if not row: return
        payload=row.payload or {}; job_type=row.job_type; target=row.target; tenant_id=row.tenant_id
    tenant_token = tenant_context.set(tenant_id)
    job=JobRecord(job_id,job_type,target)
    with session_scope() as db:
        row=db.get(JobRow,job_id)
        if row: row.status=JobStatus.RUNNING.value; row.started_at=utcnow()
    job.log("Worker picked up job")
    try:
        if job_type == "full":
            result=await manager.run(FullScanRequest(**payload), job=job)
        elif job_type == "network":
            await job.checkpoint("network"); result=await network_scanner.scan(target=target, scan_type=payload.get("scan_type","quick"), ports=payload.get("ports"), timing=payload.get("timing"))
        elif job_type == "web":
            await job.checkpoint("web"); result=await web_scanner.scan(target_url=target, profile=payload.get("profile","balanced"), max_pages=payload.get("max_pages"), max_depth=payload.get("max_depth"))
        else:
            raise RuntimeError(f"Unsupported durable job type: {job_type}")
        if job_type in {"network", "web", "api_security"}:
            try:
                pipeline = await correlate_and_escalate(
                    tenant_id=tenant_id, result=result, job_id=job_id,
                    run_gemini=bool(settings.GEMINI_API_KEY),
                )
                job.log(f"SOC pipeline: {pipeline}")
            except Exception as exc:
                job.log(f"SOC pipeline warning: {str(exc)[:1000]}")
        job.result=result; job.progress=100; job.current_engine=None; job.status=JobStatus.COMPLETED; job.log("Worker completed job")
    except asyncio.CancelledError:
        job.status=JobStatus.CANCELLED; job.error_message="Job cancelled"
    except Exception as exc:
        job.status=JobStatus.FAILED; job.error_message=str(exc)[:2000]; job.log(f"Worker failed: {exc}")
    finally:
        with session_scope() as db:
            row=db.get(JobRow,job_id)
            if row: row.finished_at=utcnow()
        tenant_context.reset(tenant_token)

async def run_continuous_item(r, item: dict, worker_id: str):
    lock_key = ENQUEUE_LOCK_PREFIX + item["schedule_id"]
    try:
        return await ContinuousScanner.execute(item, worker_id)
    finally:
        # Release the enqueue lock only if this worker still owns it.
        try:
            owner = r.get(lock_key)
            if owner == worker_id:
                r.delete(lock_key)
        except Exception:
            pass

async def main():
    if not settings.REDIS_URL: raise SystemExit("REDIS_URL is required for worker mode")
    r=redis.Redis.from_url(settings.REDIS_URL,decode_responses=True)
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    last_schedule_tick = 0.0
    loop = asyncio.get_running_loop()
    while True:
        now = loop.time()
        if now - last_schedule_tick >= 5:
            try:
                ContinuousScanner.enqueue_due(r, worker_id, limit=20)
            except Exception:
                # Scheduling is best-effort; durable rows remain in Postgres and
                # another worker replica can retry on the next tick.
                pass
            last_schedule_tick = now

        item = r.blpop([settings.JOB_QUEUE_NAME, CONTINUOUS_QUEUE], timeout=2)
        if not item:
            continue
        queue_name, payload = item
        if queue_name == CONTINUOUS_QUEUE:
            try:
                await run_continuous_item(r, json.loads(payload), worker_id)
            except Exception:
                # execute() records the failure on the schedule.
                pass
        else:
            await run_job(payload)

if __name__ == "__main__": asyncio.run(main())
