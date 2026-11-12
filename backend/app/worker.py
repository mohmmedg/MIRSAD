"""Durable MIRSAD worker using Redis Streams consumer groups."""
from __future__ import annotations
import asyncio, json, logging, os, signal, socket, time, uuid
import redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s worker: %(message)s")
logger = logging.getLogger("mirsad.worker")

# 2026-09-22 fix (توزيع ذكي للفحوصات المتزامنة):
# كان Semaphore محلي per-process — لو شغّلت عدة worker containers بالتوازي
# (بالضبط طريقة تسريع الفحص المطلوبة)، كل container يطبق سقفه الخاص، فالسقف
# الفعلي الكلي يتضاعف بعدد الـ containers بدل ما يبقى ثابت عند
# MAX_CONCURRENT_ENGINES. الآن يُستخدم سقف موزّع عبر Redis (نفس Redis
# المستخدم أصلاً لطابور المهام) فيبقى صحيح عالمياً مهما زاد عدد الـ workers،
# بالإضافة لسقف مستقل لكل هدف فحص (MAX_CONCURRENT_ENGINES_PER_TARGET) حتى
# لا يتراكم الضغط على نفس الموقع المفحوص لو صار له أكثر من job بنفس اللحظة.
from app.core.distributed_semaphore import distributed_slot, target_key as _target_key
from sqlalchemy import select
from sqlalchemy.orm import defer
from app.core.config import settings
from app.core.database import JobRow, ScanRow, jsonable, require_rls_bypass_role, session_scope_sync, utcnow, with_db_retry
from app.core.auth_context import tenant_context
from app.core.job_manager import JobRecord
from app.core.finding_pipeline import correlate_and_escalate
from app.core.architecture.manager import manager
from app.modules.network_scan.scanner import NetworkScanner
from app.modules.web_scan.scanner import WebScanner
from app.schemas.jobs import JobStatus
from app.schemas.platform import FullScanRequest
from app.modules.continuous import ContinuousScanner, CONTINUOUS_QUEUE, ENQUEUE_LOCK_PREFIX
from app.core.policy_enforcement import scan_policy, scan_timeout_seconds
from app.core.worker_liveness import worker_liveness_loop
from app.core.job_payload_crypto import restore_job_payload
from app.core.redis_queue import STREAM, GROUP, MAX_ATTEMPTS, VISIBILITY_MS, ack, dead_letter, ensure_group, enqueue, enqueue_recovery_once, recovery_marker_key, reclaim, read

network_scanner=NetworkScanner(); web_scanner=WebScanner()

async def _heartbeat_loop(job: JobRecord, stop: asyncio.Event):
    while not stop.is_set():
        try:
            await job.heartbeat()
        except Exception:
            logger.warning("Job heartbeat update failed for %s", getattr(job, "job_id", "?"), exc_info=True)
        try:
            await asyncio.wait_for(stop.wait(), timeout=15)
        except asyncio.TimeoutError:
            pass


async def _control_loop(job: JobRecord, stop: asyncio.Event, worker_task: asyncio.Task):
    while not stop.is_set():
        try:
            status=job.status
            if status == JobStatus.CANCEL_REQUESTED and not worker_task.done():
                worker_task.cancel()
                return
        except Exception:
            logger.debug("Job cancel-status check failed for %s", getattr(job, "job_id", "?"), exc_info=True)
        try: await asyncio.wait_for(stop.wait(), timeout=3)
        except asyncio.TimeoutError: pass

async def run_job(job_id: str, worker_id: str) -> bool:
    return await _run_job_inner(job_id, worker_id)


async def _run_job_inner(job_id: str, worker_id: str) -> bool:
    def _load():
        with session_scope_sync() as db:
            row=db.get(JobRow,job_id)
            if not row:
                logger.warning("Job %s not found in the database; dropping its Redis delivery", job_id)
                return None
            # Redis delivery is at-least-once. A duplicate delivery must never
            # re-run a scan that already reached a terminal state, nor start a
            # second worker while another worker still holds a live lease.
            # A durable message may be delivered more than once. Only pending
            # jobs, or running jobs whose lease has genuinely expired, are
            # eligible for execution. In particular, PAUSED and
            # CANCEL_REQUESTED must never be resurrected by Redis reclaim.
            if row.status not in {JobStatus.PENDING.value, JobStatus.RUNNING.value}:
                return None
            now = utcnow()
            if row.status == JobStatus.RUNNING.value and row.lease_until and row.lease_until > now:
                return None
            payload=row.payload or {}; job_type=row.job_type; target=row.target; tenant_id=row.tenant_id
            attempt=(row.attempt_count or 0)+1
            from datetime import timedelta
            row.attempt_count=attempt; row.lease_owner=worker_id; row.lease_until=now+timedelta(seconds=120)
            return payload,job_type,target,tenant_id,attempt
    # Blocking SQLAlchemy work must not run on the event loop that also drives heartbeats,
    # cancel polling and every other in-flight job (2026-10-17).
    loaded=await asyncio.to_thread(with_db_retry,_load)
    if loaded is None: return True
    payload,job_type,target,tenant_id,attempt=loaded
    payload = restore_job_payload(payload)
    tenant_token = tenant_context.set(tenant_id)
    job=JobRecord(job_id,job_type,target)
    if job_type == "web":
        job.initialize_stages([
            ("target_validation","Target validation"),
            ("target_reachability","Target reachability"),
            ("web_crawl","Web crawling"),
            ("source_intelligence","Source intelligence"),
            ("external_scanners","External detectors"),
            ("finalize","Finalize results"),
        ])
        job.set_stage("target_validation","completed",progress=100,message="Target validated by queue admission")
        job.set_stage("web_crawl","running",progress=10,message="Crawling reachable web application")
    stop=asyncio.Event(); hb=asyncio.create_task(_heartbeat_loop(job, stop))
    # Report-only stall detection in its own thread (see app/core/stall_watchdog.py).
    from app.core.stall_watchdog import StallWatchdog
    _loop=asyncio.get_running_loop(); _main_task=asyncio.current_task()
    _stall_fired: list = []  # set when the watchdog (not the user/SIGTERM) cancelled this attempt
    watchdog=StallWatchdog(job, threshold_seconds=settings.WORKER_STALL_SECONDS,
                           check_seconds=settings.WORKER_STALL_CHECK_SECONDS, redis_url=settings.REDIS_URL or None,
                           dead_seconds=float(getattr(settings, "WORKER_STALL_CANCEL_SECONDS", 0) or 0),
                           on_dead=lambda _idle: (_stall_fired.append(_idle), _loop.call_soon_threadsafe(_main_task.cancel)))
    watchdog.start()
    control=asyncio.create_task(_control_loop(job, stop, asyncio.current_task()))
    terminal_failure=False
    try:
        def _mark_running():
            from datetime import timedelta
            with session_scope_sync() as db:
                row=db.get(JobRow,job_id)
                if row:
                    row.status=JobStatus.RUNNING.value; row.started_at=row.started_at or utcnow(); row.heartbeat_at=utcnow(); row.lease_owner=worker_id
                    row.lease_until=utcnow()+timedelta(seconds=120)
                scan=db.get(ScanRow, job_id)
                if scan and scan.tenant_id == tenant_id: scan.status=JobStatus.RUNNING.value
        await asyncio.to_thread(with_db_retry, _mark_running)
        job.start_execution(count_attempt=False)  # attempt already counted in _load
        job.log(f"Worker picked up job (attempt {attempt})")
        # Immediate target check (before any engine starts): is the target running and reachable from
        # the scanner containers? Result is written to the live log; an unreachable target fails the
        # job at once and TERMINALLY (no retry), instead of burning minutes on engines that can't test it.
        # ("full" jobs do the same check inside manager.run, where it is shown as the target_reachability stage.)
        if job_type == "web" and getattr(settings,"PRECHECK_TARGET_REACHABLE",True):
            from app.modules.external_scanners.engines import probe_target_reachability
            job.set_stage("target_reachability","running",progress=10,message="Checking the target is up and reachable from the scanner containers")
            try:
                probe=await probe_target_reachability(target)
            except Exception as _pexc:
                probe={"checked":False,"reachable":None,"state":"unchecked","message_ar":f"تعذّر تنفيذ فحص الوصول: {type(_pexc).__name__}"}
            job.log(f"[فحص الهدف] {probe.get('message_ar')}")
            _msg=str(probe.get("message_ar"))[:500]
            if probe.get("reachable") is False and getattr(settings,"FAIL_FAST_ON_UNREACHABLE",True):
                job.set_stage("target_reachability","failed",progress=100,message=_msg)
                raise RuntimeError(f"TARGET_UNREACHABLE[{probe.get('state')}]: {probe.get('message_ar')}")
            job.set_stage("target_reachability","completed" if probe.get("reachable") else ("partial" if probe.get("reachable") is False else "skipped"),progress=100,message=_msg)
        elif job_type == "web":
            job.set_stage("target_reachability","skipped",progress=100,message="Reachability pre-check disabled")
        duration=scan_timeout_seconds(tenant_id)
        async def execute():
            if job_type == "full":
                return await manager.run(FullScanRequest(**payload), job=job)
            elif job_type == "network":
                await job.checkpoint("network")
                return await network_scanner.scan(target=target, scan_type=payload.get("scan_type","quick"), ports=payload.get("ports"), timing=payload.get("timing"))
            elif job_type == "web":
                await job.checkpoint("web")
                return await web_scanner.scan(
                    target_url=target,
                    profile=payload.get("profile","balanced"),
                    max_pages=payload.get("max_pages"),
                    max_depth=payload.get("max_depth"),
                    run_external=True,
                    safe_mode=payload.get("safe_mode","safe"),
                    destructive_confirmation=bool(payload.get("destructive_confirmation",False)),
                )
            else:
                raise RuntimeError(f"Unsupported durable job type: {job_type}")
        # 2026-09-22 (توزيع ذكي): سقف عالمي موزّع عبر كل الـ workers +
        # سقف مستقل لنفس الهدف، حتى لو تعددت الـ containers أو تعددت
        # الفحوصات على نفس الموقع بنفس اللحظة. wait_timeout=None يعني
        # الانتظار بالدور (queueing) بدل رفض الفحص لو السقف ممتلئ مؤقتاً.
        global_limit = int(getattr(settings, "MAX_CONCURRENT_ENGINES", 8))
        per_target_limit = int(getattr(settings, "MAX_CONCURRENT_ENGINES_PER_TARGET", 2))
        job.set_stage("queue", "waiting", message="Waiting for a free concurrency slot")
        async with distributed_slot("engines:global", limit=global_limit):
            async with distributed_slot(f"engines:target:{_target_key(target)}", limit=per_target_limit):
                job.set_stage("scan", "running", message="Slot acquired; scan started")
                result=await asyncio.wait_for(execute(), timeout=duration)
        if job_type == "web":
            # manager.run() owns canonical external evidence persistence. The worker
            # must not persist the same payload again; otherwise at-least-once job
            # delivery can create duplicate EngineResult rows and evidence.
            ext=getattr(result,"external_scanners",{}) or {}
            missing=[name for name,payload in ext.items() if isinstance(payload,dict) and not payload.get("engine_result_id")]
            if missing:
                job.log(f"Canonical evidence warning: missing engine_result_id for {','.join(missing)}")
        if job_type in {"network","web","api_security"}:
            try:
                pipeline=await correlate_and_escalate(tenant_id=tenant_id,result=result,job_id=job_id,run_gemini=bool(settings.GEMINI_API_KEY)); job.log(f"SOC pipeline: {pipeline}")
            except Exception as exc: job.log(f"SOC pipeline warning: {str(exc)[:1000]}")
        if job_type == "web":
            si = getattr(result, "source_intelligence", {}) or {}
            ext = getattr(result, "external_scanners", {}) or {}
            job.set_stage("web_crawl", "completed", progress=100, message=f"{len(getattr(result, 'endpoints', []) or [])} endpoint(s) discovered")
            job.set_stage("source_intelligence", "completed" if si.get("status") == "COMPLETED" else ("failed" if si.get("status") == "FAILED" else "skipped"), progress=100,
                          message=f"{int((si.get('coverage') or {}).get('endpoints', 0))} source-derived endpoint(s)")
            from app.modules.external_scanners.engines import EXTERNAL_ENGINE_NAMES
            names = EXTERNAL_ENGINE_NAMES
            vals = [ext.get(n, {}) for n in names]
            enabled = [v for v in vals if v.get("status") not in {"DISABLED", "SKIPPED", "UNAVAILABLE", "NOT_INSTALLED"}]
            failed = [n for n, v in zip(names, vals) if v.get("status") in {"FAILED"}]
            partial_tools = [n for n, v in zip(names, vals) if v.get("status") in {"PARTIAL"}]
            unavailable = [n for n, v in zip(names, vals) if v.get("status") in {"SKIPPED", "UNAVAILABLE", "DISABLED", "NOT_INSTALLED"}]
            if not enabled:
                reason = "; ".join(f"{n}: {ext[n].get('reason', ext[n].get('status'))}" for n in unavailable if n in ext) or "All external detectors unavailable"
                job.set_stage("external_scanners", "skipped", progress=100, message=reason)
            elif len(failed) == len(enabled):
                job.set_stage("external_scanners", "failed", progress=100, message=f"All {len(enabled)} enabled external detector(s) failed: {', '.join(failed)}")
            elif failed or partial_tools:
                job.set_stage("external_scanners", "partial", progress=100, message=f"{len(enabled)-len(failed)-len(partial_tools)}/{len(enabled)} completed; partial={', '.join(partial_tools) or 'none'}; failed={', '.join(failed) or 'none'}")
            else:
                job.set_stage("external_scanners", "completed", progress=100, message="All external detectors completed")
        # The result can be large: write it on a worker thread so the event loop (heartbeats, stall watchdog) keeps running.
        await asyncio.to_thread(setattr, job, "result", result)
        job.progress=100; job.current_engine=None
        job.set_stage("finalize","completed",progress=100,message="Scan snapshot finalized")
        from app.core.scan_health import web_terminal_status
        result_status = str(getattr(getattr(result, "status", None), "value", getattr(result, "status", "partial"))).lower()
        if job_type == "web":
            # The worker is the last terminal-state gate: never overwrite a
            # failed/partial source or a failed detector with COMPLETED.
            result_status = web_terminal_status(result_status,
                getattr(result, "external_scanners", {}) or {},
                getattr(result, "source_intelligence", None))
        job.status = (JobStatus.COMPLETED if result_status == "completed" else
                      JobStatus.FAILED if result_status == "failed" else
                      JobStatus.CANCELLED if result_status == "cancelled" else JobStatus.PARTIAL)
        if job.status != JobStatus.COMPLETED:
            job.log(f"Final scan state is {job.status.value}; some requested tests may be incomplete")
        job.log("Worker completed job")
        def _sync_scan_row():
            with session_scope_sync() as db:
                scan=db.get(ScanRow,job_id)
                if scan and scan.tenant_id==tenant_id:
                    scan.result=jsonable(result); scan.status=job.status.value; scan.finished_at=utcnow()
        await asyncio.to_thread(with_db_retry, _sync_scan_row)
        return True
    except asyncio.CancelledError:
        if _stall_fired:
            # The stall watchdog cancelled us, nobody asked for a cancel. Reporting CANCELLED here
            # looked like a user action and was terminal; record it as a failure so the normal
            # retry/recovery path (bounded by the attempt budget) applies.
            job.status=JobStatus.FAILED
            job.error_message=f"Stalled: no progress for {int(_stall_fired[0])}s (watchdog cancelled this attempt)"
            job.log(job.error_message)
            return False
        job.status=JobStatus.CANCELLED; job.error_message="Job cancelled"; job.log("Job cancelled"); return True
    except Exception as exc:
        # 2026-09-16: this used to call the job.status/error_message setters
        # directly with nothing around them. Those setters already retry a
        # transient DB disconnect internally (with_db_retry), but a real,
        # longer-lived outage (a DNS blip lasting more than ~1s, say) still
        # exhausts that retry budget and re-raises — and since THIS except
        # block had no guard of its own, that second exception used to escape
        # run_job entirely, uncaught, and crash the whole worker PROCESS (see
        # "worker-1 exited with code 1 (restarting)" in the 2026-09-16 log).
        # Docker then restarted the container, which picked the same job back
        # up via recover_orphans() and re-ran it from scratch. Failing to
        # persist "this job failed" should never be worse than the original
        # failure — log it and move on; the outer loop below still has its
        # own safety net in case even this isn't enough.
        # Some exceptions (asyncio.TimeoutError, bare CancelledError subclasses)
        # stringify to "". Without the type name the job log only says
        # "Worker failed: " and there is no way to tell what failed, so keep the
        # type name and always log the full traceback to the worker's stdout.
        _exc_text = str(exc).strip() or repr(exc)
        _exc_text = f"{type(exc).__name__}: {_exc_text}" if not _exc_text.startswith(type(exc).__name__) else _exc_text
        logger.error("Job %s failed: %s", job_id, _exc_text, exc_info=True)
        if "TARGET_UNREACHABLE[" in _exc_text:
            terminal_failure=True  # also covers "full" jobs, where manager.run raises it
        try:
            job.status=JobStatus.FAILED; job.error_message=_exc_text[:2000]; job.log(f"Worker failed: {job.error_message}")
        except Exception as persist_exc:
            logger.error("Could not persist failure for job %s (original error: %s): %s", job_id, exc, persist_exc, exc_info=True)
        # Unreachable target is a final answer, not a transient worker fault: ACK it (no retry).
        return True if terminal_failure else False
    finally:
        stop.set(); control.cancel(); watchdog.stop(); await asyncio.gather(hb, control, return_exceptions=True)
        def _finalize_row():
            with session_scope_sync() as db:
                row=db.get(JobRow,job_id)
                if row and ((row.attempt_count or 0) > attempt or (row.lease_owner not in (None, worker_id))):
                    # Lease fencing: a newer attempt/worker owns this job now. A stale attempt that
                    # wakes up late must not overwrite its status (e.g. CANCELLED over a live run).
                    logger.warning("Job %s: stale attempt %s (row attempt=%s owner=%s) - finalize skipped",
                                   job_id, attempt, row.attempt_count, row.lease_owner)
                    return
                if row:
                    # A transient worker exception is kept recoverable until the
                    # stream consumer decides whether to retry or dead-letter it.
                    if job.status in {JobStatus.COMPLETED,JobStatus.PARTIAL,JobStatus.CANCELLED}:
                        row.status=job.status.value; row.finished_at=utcnow()
                    elif job.status == JobStatus.FAILED and terminal_failure:
                        row.status=JobStatus.FAILED.value; row.error_message=job.error_message; row.finished_at=utcnow(); row.lease_owner=None; row.lease_until=None
                    elif job.status == JobStatus.FAILED:
                        row.error_message=job.error_message; row.heartbeat_at=utcnow(); row.lease_owner=worker_id; row.lease_until=utcnow()
                    row.result=jsonable(job.result) if job.result is not None else row.result
                scan=db.get(ScanRow,job_id)
                if scan and scan.tenant_id==tenant_id and terminal_failure and job.status == JobStatus.FAILED:
                    scan.status=JobStatus.FAILED.value; scan.error_message=job.error_message; scan.finished_at=utcnow()
                elif scan and scan.tenant_id==tenant_id and job.status in {JobStatus.COMPLETED,JobStatus.PARTIAL,JobStatus.CANCELLED}:
                    scan.status=job.status.value; scan.error_message=job.error_message; scan.finished_at=utcnow(); scan.result=jsonable(job.result) if job.result is not None else scan.result
        try:
            # Terminal write: runs in a thread but is shielded, so a late cancel of this task
            # cannot abandon it half-way (the thread keeps going and commits).
            await asyncio.shield(asyncio.to_thread(with_db_retry,_finalize_row))
        except Exception as exc:
            # Same reasoning as above: this write finalizes bookkeeping only.
            # If the DB is genuinely unreachable there is nothing more this
            # process can safely do about it — log and let recover_orphans()
            # reconcile the row once the DB is back, rather than crashing.
            logger.error("Could not finalize row for job %s: %s", job_id, exc, exc_info=True)
        try:
            job.finish_execution()
        except Exception:
            logger.warning("finish_execution failed for job %s", job_id, exc_info=True)
        try:
            # Make sure every queued progress/log/event write has been attempted before this job handle is dropped.
            job.flush_writes(30.0)
        except Exception:
            logger.warning("flush of background job writes failed for %s", job_id, exc_info=True)
        tenant_context.reset(tenant_token)


def interrupt_stale_engine_results() -> int:
    """Turn engine_results left RUNNING by a dead execution into INTERRUPTED.

    A worker restart/crash used to leave rows such as nuclei/sqlmap RUNNING
    forever with no duration. A row is stale when its scan has no live job:
    the job is not RUNNING/PAUSED/CANCEL_REQUESTED with an unexpired lease.
    engine_results is tenant-isolated (RLS), so each tenant is swept in its own
    tenant-scoped session. Safe to call repeatedly.
    """
    from app.core.database import EngineResultRow
    now=utcnow()
    live_states=[JobStatus.RUNNING.value, JobStatus.PAUSED.value, JobStatus.CANCEL_REQUESTED.value]
    def _sweep():
        with session_scope_sync() as db:
            tenants=[t for (t,) in db.execute(select(JobRow.tenant_id).distinct()).all() if t]
            live={j for (j,) in db.execute(select(JobRow.job_id).where(
                JobRow.status.in_(live_states), JobRow.lease_until.is_not(None), JobRow.lease_until >= now)).all()}
        total=0
        for tenant in tenants:
            with session_scope_sync(tenant_id=tenant) as db:
                rows=db.scalars(select(EngineResultRow).where(
                    EngineResultRow.tenant_id==tenant, EngineResultRow.status=="RUNNING")).all()
                for row in rows:
                    if row.scan_id in live: continue
                    row.status="INTERRUPTED"
                    row.finished_at=row.finished_at or now
                    try:
                        if row.started_at and row.duration_seconds is None:
                            row.duration_seconds=max(0.0,(now-row.started_at).total_seconds())
                    except Exception:
                        logger.debug("suppressed non-fatal error", exc_info=True)
                    meta=dict(row.metadata_json or {})
                    meta["interrupted_at"]=now.isoformat()
                    meta["interrupted_reason"]="Execution ended without finalizing this engine (worker restart, crash or stall)"
                    row.metadata_json=meta
                    total+=1
        return total
    count=with_db_retry(_sweep)
    if count:
        logger.warning("Marked %d stale RUNNING engine result(s) as INTERRUPTED", count)
    return count


def recover_pending():
    if not settings.WORKER_RESUME_INTERRUPTED_JOBS:
        return []
    now=utcnow(); pending=[]
    def _read():
        with session_scope_sync() as db:
            return list(db.scalars(select(JobRow.job_id).where(JobRow.status==JobStatus.PENDING.value, JobRow.created_at < now)).all())
    pending=with_db_retry(_read)
    if settings.REDIS_URL:
        r=redis.Redis.from_url(settings.REDIS_URL,decode_responses=True); ensure_group(r)
        for jid in pending: enqueue_recovery_once(r,jid)
    return pending

def _finalize_as_cancelled(db, row, now, message: str):
    row.status=JobStatus.CANCELLED.value; row.error_message=message
    row.finished_at=now; row.lease_owner=None; row.lease_until=None
    scan=db.get(ScanRow,row.job_id)
    if scan:
        scan.status=JobStatus.CANCELLED.value; scan.error_message=message; scan.finished_at=now

def discard_stale_jobs_on_start():
    """Startup-only: prevent any scan from a previous deployment from running.

    RUNNING jobs are first moved to CANCEL_REQUESTED so an older worker process
    that is still alive sees the cancellation in its control loop and stops the
    scan. PENDING jobs are finalized immediately because they have not started
    execution. This is stronger than simply marking every row CANCELLED:
    an old worker cannot be allowed to keep hammering a target after a new
    deployment starts.
    """
    now=utcnow()
    def _purge():
        with session_scope_sync() as db:
            rows=db.scalars(select(JobRow).where(JobRow.status.in_([
                JobStatus.RUNNING.value, JobStatus.PENDING.value, JobStatus.CANCEL_REQUESTED.value,
            ]))).all()
            for row in rows:
                if row.status == JobStatus.RUNNING.value:
                    row.status=JobStatus.CANCEL_REQUESTED.value
                    row.error_message="Cancelled by deployment startup; previous execution will not be resumed"
                    if hasattr(row, "updated_at"):
                        row.updated_at=now
                    scan=db.get(ScanRow,row.job_id)
                    if scan:
                        scan.error_message=row.error_message
                else:
                    _finalize_as_cancelled(
                        db,row,now,
                        "Left over from a previous deployment; not resumed (WORKER_RESUME_INTERRUPTED_JOBS=false)"
                    )
            return [r.job_id for r in rows]
    purged=with_db_retry(_purge)
    if purged:
        logger.warning(
            "Invalidated %d stale job(s) from previous deployment (running jobs requested for cancellation): %s",
            len(purged), ", ".join(purged)
        )
    return purged


def recover_orphans(worker_id: str):
    """Recover jobs whose worker lease expired without trusting Redis state.

    Two distinct situations land here after a worker dies mid-scan:

    1. The job was plainly RUNNING (no cancel was ever requested) — the only
       safe move is to re-run it, since this codebase has no fine-grained
       resume-from-checkpoint for a partially completed scan.

    2. The job was CANCEL_REQUESTED — the person had already asked for it to
       stop before the worker died. Previously this branch was invisible to
       recover_orphans (it only matched status==RUNNING), so a job like this
       stayed stuck in CANCEL_REQUESTED forever: never finalized, but also
       never picked back up. Worse, if the row briefly read as RUNNING when
       the process died (the cancel signal hadn't been persisted yet), the
       old code would silently re-enqueue and fully re-run a scan the user
       had already told MIRSAD to stop — re-hammering the same target with
       no indication that a "completed" cancellation had actually resumed.
       Both cases are now resolved by *finalizing* to CANCELLED instead of
       resurrecting the job.
    """
    now=utcnow(); recovered=[]
    def _reconcile():
        with session_scope_sync() as db:
            cancel_rows=db.scalars(select(JobRow).options(defer(JobRow.payload), defer(JobRow.result)).where(
                JobRow.status==JobStatus.CANCEL_REQUESTED.value,
                JobRow.heartbeat_at.is_not(None), JobRow.heartbeat_at < now,
            )).all()
            for row in cancel_rows:
                if row.lease_until and row.lease_until >= now: continue
                row.status=JobStatus.CANCELLED.value; row.error_message="Job cancelled (worker lease expired mid-cancel)"
                row.finished_at=now; row.lease_owner=None; row.lease_until=None
                scan=db.get(ScanRow,row.job_id)
                if scan: scan.status=JobStatus.CANCELLED.value; scan.error_message=row.error_message; scan.finished_at=now

            rows=db.scalars(select(JobRow).options(defer(JobRow.payload), defer(JobRow.result)).where(JobRow.status==JobStatus.RUNNING.value, JobRow.heartbeat_at.is_not(None), JobRow.heartbeat_at < now)).all()
            found=[]
            for row in rows:
                if row.lease_until and row.lease_until >= now: continue
                if (row.attempt_count or 0) >= MAX_ATTEMPTS:
                    row.status=JobStatus.FAILED.value; row.error_message="Worker lease expired; retry budget exhausted"; row.finished_at=now
                    continue
                if not settings.WORKER_RESUME_INTERRUPTED_JOBS:
                    _finalize_as_cancelled(db,row,now,"Interrupted by worker restart; not resumed (WORKER_RESUME_INTERRUPTED_JOBS=false)")
                    continue
                row.status=JobStatus.PENDING.value; row.lease_owner=None; row.lease_until=None; found.append(row.job_id)
            return found
    recovered=with_db_retry(_reconcile)
    if settings.REDIS_URL:
        r=redis.Redis.from_url(settings.REDIS_URL,decode_responses=True); ensure_group(r)
        for jid in recovered: enqueue(r,jid,"recovery")
    return recovered

async def _defectdojo_sync_once():
    try:
        from app.integrations.defectdojo.retry import process_due_job
        await process_due_job()
    except Exception as exc:
        logger.error("DefectDojo retry pass failed: %s", exc, exc_info=True)

async def main():
    from app.core.file_logging import setup_file_logging
    setup_file_logging("worker")
    if not settings.REDIS_URL: raise SystemExit("REDIS_URL is required for worker mode")
    r=redis.Redis.from_url(settings.REDIS_URL,decode_responses=True,socket_connect_timeout=2,socket_timeout=5,health_check_interval=30)
    ensure_group(r)
    require_rls_bypass_role()
    worker_id=f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    logger.info("Worker %s started; connected to Redis stream=%s group=%s", worker_id, STREAM, GROUP)

    # Liveness must not be coupled to the dispatcher below: that loop awaits
    # complete scan tasks and can otherwise leave both health heartbeats stale
    # for the full duration of a long-running scan.
    shutdown = asyncio.Event()
    current_job_tasks: set[asyncio.Task] = set()
    liveness_task = asyncio.create_task(worker_liveness_loop(r, worker_id, shutdown))

    if not settings.WORKER_RESUME_INTERRUPTED_JOBS:
        try: await asyncio.to_thread(discard_stale_jobs_on_start)
        except Exception as exc: logger.error("Stale-job discard failed: %s", exc, exc_info=True)
    try: await asyncio.to_thread(interrupt_stale_engine_results)
    except Exception as exc: logger.error("Stale engine-result sweep failed: %s", exc, exc_info=True)

    # 2026-09-16 fix: stopping the stack (docker compose down / Ctrl+C) used to
    # just kill this process mid-scan with no cleanup at all. The job row was
    # left "running" with a lease that meant nothing anymore, so the NEXT
    # `docker compose up` — potentially days later — silently resumed and
    # re-ran that exact scan via recover_orphans() below, with no browser
    # ever opened by the person and no way to tell it was about to happen.
    # On a graceful stop signal (SIGTERM: `docker compose down`/`stop`;
    # SIGINT: Ctrl+C) we now cancel whatever job is in flight so it finalizes
    # as CANCELLED — a terminal state recover_orphans() never resurrects.
    def _request_shutdown(sig_name: str):
        logger.info("Received %s — cancelling %d in-flight job(s) and shutting down", sig_name, len(current_job_tasks))
        shutdown.set()
        for task in list(current_job_tasks):
            if not task.done():
                task.cancel()

    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
    except NotImplementedError:
        # add_signal_handler isn't available on every platform (e.g. native
        # Windows without WSL); the container this actually runs in is Linux,
        # so this is just a defensive fallback, not the expected path.
        logger.warning("Signal handlers unavailable on this platform; graceful cancel-on-stop is disabled")

    last_reap=0.0; dd_task: asyncio.Task | None = None
    while not shutdown.is_set():
        now=asyncio.get_running_loop().time()
        if now-last_reap>=30:
            try:
                await asyncio.to_thread(recover_orphans, worker_id); await asyncio.to_thread(recover_pending); await asyncio.to_thread(interrupt_stale_engine_results)
            except Exception as exc:
                logger.error("Recovery pass failed: %s", exc, exc_info=True)
            # DefectDojo sync can wait up to DEFECTDOJO_IMPORT_WAIT_SECONDS (900s) per import.
            # It must never run inline here: awaiting it froze the dispatcher, so queued scans
            # stayed PENDING (lag>0, 0 consumers reading) while the worker still looked healthy.
            if dd_task is None or dd_task.done():
                dd_task=asyncio.create_task(_defectdojo_sync_once())
            last_reap=now
        try:
            claimed=await asyncio.to_thread(reclaim,r,worker_id,VISIBILITY_MS,20)
            items=claimed or await asyncio.to_thread(read,r,worker_id,1,2000)
        except Exception as exc:
            # Previously swallowed with zero logging — this made a broken
            # Redis connection (bad password, ACL, network) indistinguishable
            # from "idle, no jobs queued". Jobs stayed at 0%/pending forever
            # with no error anywhere. Log it so the real cause is visible in
            # `docker compose logs worker`.
            logger.error("Redis poll failed (will retry in 2s): %s", exc, exc_info=True)
            await asyncio.sleep(2); continue
        if not items:
            continue

        # A worker used to process exactly one scan at a time. That made a
        # long ZAP/FFUF assessment block every later scan even though the
        # distributed engine semaphore already limits scanner pressure. Run a
        # small number of complete jobs concurrently instead; DB pools and the
        # global engine semaphore remain the hard resource controls.
        max_jobs = max(1, int(getattr(settings, "WORKER_MAX_CONCURRENT_JOBS", 2)))
        job_gate = asyncio.Semaphore(max_jobs)

        async def _process_delivery(message_id, fields):
            async with job_gate:
                if shutdown.is_set():
                    return
                jid=fields.get("job_id")
                if not jid:
                    await asyncio.to_thread(dead_letter,r,message_id,fields,"missing_job_id")
                    return
                task = asyncio.create_task(run_job(jid,worker_id))
                current_job_tasks.add(task)
                try:
                    ok = await task
                except asyncio.CancelledError:
                    ok = True
                except Exception as exc:
                    logger.error("run_job crashed unexpectedly for %s: %s", jid, exc, exc_info=True)
                    ok = False
                finally:
                    current_job_tasks.discard(task)
                if ok:
                    await asyncio.to_thread(ack,r,message_id)
                    if jid:
                        try: await asyncio.to_thread(r.delete,recovery_marker_key(jid))
                        except Exception: logger.debug("Could not clear recovery marker for %s", jid, exc_info=True)
                    return
                # Re-enqueue as a fresh delivery; ACK the failed delivery to
                # avoid poison-message hot loops. Postgres attempt_count is canonical.
                def _read_attempts():
                    with session_scope_sync() as db:
                        row=db.get(JobRow,jid); return (row.attempt_count or 0) if row else MAX_ATTEMPTS
                attempts=await asyncio.to_thread(with_db_retry,_read_attempts)
                if attempts < MAX_ATTEMPTS:
                    await asyncio.to_thread(r.delete,recovery_marker_key(jid))
                    await asyncio.to_thread(enqueue,r,jid,"retry")
                    def _reset_for_retry():
                        with session_scope_sync() as db:
                            row=db.get(JobRow,jid)
                            if row:
                                row.status=JobStatus.PENDING.value
                                row.lease_owner=None
                                row.lease_until=None
                    await asyncio.to_thread(with_db_retry,_reset_for_retry)
                    await asyncio.to_thread(ack,r,message_id)
                else:
                    await asyncio.to_thread(dead_letter,r,message_id,fields,"retry_budget_exhausted")

        await asyncio.gather(*(_process_delivery(message_id, fields) for message_id, fields in items))
    shutdown.set()
    await liveness_task
    logger.info("Worker %s shut down cleanly", worker_id)

if __name__=="__main__": asyncio.run(main())
