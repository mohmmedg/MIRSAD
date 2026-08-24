from __future__ import annotations

import asyncio
import uuid
from typing import Any, Awaitable, Callable

from app.core.config import settings
from app.core.database import JobRow, init_db_with_retry, jsonable, session_scope, utcnow
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import scan_policy, scan_slot
from app.schemas.jobs import JobSnapshot, JobStatus

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None


def _owned_row(db, job_id):
    row=db.get(JobRow, job_id)
    if not row:
        return None
    tid=tenant_context.get()
    # Fail CLOSED: if there is no tenant context on this call (e.g. a future
    # caller forgets to set it), a job must never be returned as if it were
    # unowned/global. Only two cases are legitimate: tid matches the row's
    # tenant, or the row itself belongs to the "legacy" tenant that
    # JobManager.create() falls back to when it, too, is called without a
    # tenant context (internal/system jobs, or tests exercising JobManager
    # directly). Everywhere else, no tid means no access, not "any tenant's
    # data" -- and a real tenant's job stays invisible to an uncontexted
    # caller either way.
    if tid is None:
        return row if row.tenant_id == "legacy" else None
    return row if row.tenant_id == tid else None

class JobRecord:
    """DB-backed job handle. Mutations are immediately durable."""
    def __init__(self, job_id: str, job_type: str, target: str, task: asyncio.Task | None = None):
        self.job_id, self.job_type, self.target, self.task = job_id, job_type, target, task
        self.pause_event = asyncio.Event(); self.pause_event.set()

    def _row(self):
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            tid=tenant_context.get()
            if row and tid and row.tenant_id != tid: return None
            return row

    @property
    def status(self) -> JobStatus:
        row=self._row(); return JobStatus(row.status) if row else JobStatus.FAILED
    @status.setter
    def status(self, value: JobStatus):
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            if row: row.status=value.value
    @property
    def progress(self):
        row=self._row(); return row.progress if row else 0
    @progress.setter
    def progress(self, value):
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            if row: row.progress=max(0,min(100,int(value)))
    @property
    def current_engine(self):
        row=self._row(); return row.current_engine if row else None
    @current_engine.setter
    def current_engine(self, value):
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            if row: row.current_engine=value
    @property
    def result(self):
        row=self._row(); return row.result if row else None
    @result.setter
    def result(self, value):
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            if row: row.result=jsonable(value)
    @property
    def error_message(self):
        row=self._row(); return row.error_message if row else None
    @error_message.setter
    def error_message(self, value):
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            if row: row.error_message=str(value)[:2000] if value else None
    def log(self, message: str):
        line=f"{utcnow().isoformat()} {str(message)[:1000]}"
        with session_scope() as db:
            row=_owned_row(db, self.job_id)
            if row:
                row.logs=(row.logs or [])+ [line]
                row.logs=row.logs[-settings.MAX_JOB_LOGS:]
    async def checkpoint(self, engine: str | None = None):
        if engine: self.current_engine=engine
        while True:
            status=self.status
            if status == JobStatus.CANCELLED: raise asyncio.CancelledError
            if status != JobStatus.PAUSED: return
            self.log("Waiting while paused")
            await asyncio.sleep(0.5)

    def snapshot(self) -> JobSnapshot:
        row=self._row()
        if not row: raise KeyError(self.job_id)
        duration=None
        if row.started_at:
            end=row.finished_at or utcnow(); duration=max(0,(end-row.started_at).total_seconds())
        return JobSnapshot(job_id=row.job_id,job_type=row.job_type,target=row.target,status=JobStatus(row.status),
            progress=row.progress,current_engine=row.current_engine,logs=(row.logs or [])[-100:],
            created_at=row.created_at,started_at=row.started_at,finished_at=row.finished_at,
            duration_seconds=duration,error_message=row.error_message,result=row.result)


class JobManager:
    def __init__(self):
        if settings.DB_AUTO_CREATE_SCHEMA: init_db_with_retry()
        self._tasks: dict[str,asyncio.Task]={}

    async def create(self, job_type: str, target: str, runner: Callable[[JobRecord], Awaitable[Any]] | None = None,
                     start: bool = True, payload: dict | None = None) -> JobRecord:
        tenant_id=tenant_context.get() or "legacy"
        if tenant_id != "legacy":
            policy=scan_policy(tenant_id)
            with session_scope(tenant_id) as db:
                active=db.scalar(select(__import__("sqlalchemy",fromlist=["func"]).func.count()).select_from(JobRow).where(JobRow.tenant_id==tenant_id,JobRow.status.in_([JobStatus.PENDING.value,JobStatus.RUNNING.value]))) or 0
            if int(active) >= int(policy["max_concurrent_scans"]):
                from fastapi import HTTPException
                raise HTTPException(429, "Maximum concurrent scans reached for this tenant")
        job=JobRecord(str(uuid.uuid4()),job_type,target)
        with session_scope() as db:
            db.add(JobRow(job_id=job.job_id,tenant_id=tenant_context.get() or "legacy",job_type=job_type,target=target,status=JobStatus.PENDING.value,
                          progress=0,logs=[],payload=payload or {},created_at=utcnow()))
        if start and runner: self.start(job,runner)
        return job

    def _redis(self):
        if not settings.JOB_QUEUE_ENABLED or not settings.REDIS_URL or redis is None: return None
        return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

    def start(self, job: JobRecord, runner: Callable[[JobRecord], Awaitable[Any]], payload: dict | None = None):
        r=self._redis()
        if r is not None and not settings.WORKER_MODE:
            try:
                with session_scope() as db:
                    row=_owned_row(db,job.job_id)
                    if row and payload is not None: row.payload=payload
                r.rpush(settings.JOB_QUEUE_NAME, job.job_id)
                job.log("Job queued")
                return job
            except Exception as exc:
                job.log(f"Redis unavailable; using local worker: {exc}")
        if job.job_id not in self._tasks or self._tasks[job.job_id].done():
            task=asyncio.create_task(self._execute(job,runner),name=f"scan-job-{job.job_id}")
            self._tasks[job.job_id]=task; job.task=task
        return job

    async def execute(self, job, runner):
        await self._execute(job, runner)

    async def _execute(self, job, runner):
        job.status=JobStatus.RUNNING
        with session_scope() as db:
            row=_owned_row(db,job.job_id)
            if row: row.started_at=utcnow()
        job.log("Job started")
        try:
            await job.checkpoint("queued")
            timeout_minutes=30
            try:
                timeout_minutes=int(scan_policy(tenant_context.get())["max_scan_duration_minutes"]) if tenant_context.get() else 30
            except Exception:
                timeout_minutes=30
            result=await asyncio.wait_for(runner(job), timeout=timeout_minutes*60)
            if job.status != JobStatus.CANCELLED:
                # Normalize scanner evidence before persisting completion. This makes
                # every web/network/API job feed the same SOC pipeline.
                if getattr(result, "module", None) in {"web", "network", "api_security"}:
                    try:
                        from app.core.finding_pipeline import correlate_and_escalate
                        tenant_id = tenant_context.get()
                        if tenant_id:
                            job.progress = 96
                            await job.checkpoint("finding_correlation")
                            pipeline = await correlate_and_escalate(
                                tenant_id=tenant_id, result=result, job_id=job.job_id,
                                run_gemini=bool(settings.GEMINI_API_KEY),
                            )
                            job.log(f"SOC pipeline: {pipeline}")
                            if hasattr(result, "scan_warnings"):
                                result.scan_warnings = list(getattr(result, "scan_warnings", [])) + [
                                    f"SOC correlation: {pipeline['findings']} findings, "
                                    f"{pipeline['incidents']} new incidents, Gemini={pipeline['gemini']}"
                                ]
                    except Exception as exc:
                        # A SOC enrichment failure must never discard a completed scan.
                        job.log(f"SOC pipeline warning: {str(exc)[:1000]}")
                job.result=result; job.progress=100; job.current_engine=None; job.status=JobStatus.COMPLETED; job.log("Job completed")
        except asyncio.TimeoutError:
            job.status=JobStatus.FAILED; job.error_message="Scan exceeded tenant maximum duration"; job.log(job.error_message)
        except asyncio.CancelledError:
            job.status=JobStatus.CANCELLED; job.error_message="Job cancelled"; job.log("Job cancelled")
        except Exception as exc:
            job.status=JobStatus.FAILED; job.error_message=str(exc)[:2000]; job.log(f"Job failed: {job.error_message}")
        finally:
            with session_scope() as db:
                row=_owned_row(db,job.job_id)
                if row: row.finished_at=utcnow()

    def get(self, job_id):
        with session_scope() as db:
            row=_owned_row(db,job_id)
            return JobRecord(row.job_id,row.job_type,row.target,self._tasks.get(job_id)) if row else None

    async def pause(self, job_id):
        job=self.get(job_id)
        if not job or job.status not in {JobStatus.RUNNING,JobStatus.PENDING}: return False
        job.status=JobStatus.PAUSED; job.log("Pause requested"); return True
    async def resume(self, job_id):
        job=self.get(job_id)
        if not job or job.status != JobStatus.PAUSED: return False
        job.status=JobStatus.RUNNING; job.log("Resume requested"); return True
    async def cancel(self, job_id):
        job=self.get(job_id)
        if not job or job.status in {JobStatus.COMPLETED,JobStatus.FAILED,JobStatus.CANCELLED}: return False
        job.status=JobStatus.CANCELLED; job.log("Cancel requested")
        task=self._tasks.get(job_id)
        if task and not task.done(): task.cancel()
        return True

    async def update(self, job, *, progress=None, engine=None, message=None):
        if progress is not None: job.progress=progress
        if engine is not None: job.current_engine=engine
        if message: job.log(message)

job_manager=JobManager()
