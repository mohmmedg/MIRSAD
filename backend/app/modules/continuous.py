"""Durable Continuous ASM scheduling.

The API process never owns a scan coroutine. Schedules are persisted in Postgres,
due work is leased/enqueued through Redis, and the worker executes the scan.
This is safe when the API/worker fleet has multiple replicas.
"""
import json, uuid
from datetime import timedelta
from sqlalchemy import select
from app.core.database import ContinuousScheduleRow, session_scope, utcnow
from app.core.auth_context import tenant_context
from app.core.architecture.manager import manager
from app.core.finding_pipeline import correlate_surface_changes
from app.core.notifier import notify
from app.schemas.platform import FullScanRequest
from app.core.config import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

CONTINUOUS_QUEUE = "continuous_scan_queue"
ENQUEUE_LOCK_PREFIX = "continuous:enqueue:"
LEASE_SECONDS = 15 * 60

_scheduler_engine = None
_scheduler_session = None

def _scheduler_db_session():
    global _scheduler_engine, _scheduler_session
    url = settings.SCHEDULER_DATABASE_URL or settings.DATABASE_URL
    if _scheduler_engine is None:
        kwargs = {
            "pool_pre_ping": True,
            "pool_recycle": int(getattr(settings, "DB_POOL_RECYCLE_SECONDS", 180)),
        }
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            kwargs["pool_size"] = int(getattr(settings, "DB_POOL_SIZE", 3))
            kwargs["max_overflow"] = int(getattr(settings, "DB_MAX_OVERFLOW", 2))
            kwargs["connect_args"] = {
                "sslmode": "require",
                "connect_timeout": int(getattr(settings, "DB_CONNECT_TIMEOUT_SECONDS", 15)),
                "keepalives": 1,
                "keepalives_idle": 30,
                "keepalives_interval": 10,
                "keepalives_count": 3,
                "application_name": "mirsad-scheduler",
            }
        _scheduler_engine = create_engine(url, **kwargs)
        _scheduler_session = sessionmaker(bind=_scheduler_engine, expire_on_commit=False)
    return _scheduler_session()

class ContinuousScanner:
    def create(self, req: FullScanRequest, interval_seconds: int):
        if interval_seconds < 300:
            raise ValueError("interval_seconds must be >= 300")
        tid = tenant_context.get() or "legacy"
        sid = str(uuid.uuid4())
        now = utcnow()
        with session_scope(tid) as db:
            db.add(ContinuousScheduleRow(
                schedule_id=sid, tenant_id=tid, target=req.target,
                request=req.model_dump(mode="json"), interval_seconds=interval_seconds,
                enabled=True, created_at=now, next_run_at=now
            ))
        return self.get(sid, tid)

    def list(self):
        tid = tenant_context.get() or "legacy"
        with session_scope(tid) as db:
            return [self._dict(r) for r in db.scalars(
                select(ContinuousScheduleRow)
                .where(ContinuousScheduleRow.tenant_id == tid)
                .order_by(ContinuousScheduleRow.created_at.desc())
            ).all()]

    def list_all(self):
        with session_scope("legacy") as db:
            return [self._dict(r) for r in db.scalars(
                select(ContinuousScheduleRow)
                .where(ContinuousScheduleRow.enabled == True)
            ).all()]

    def get(self, sid, tid):
        with session_scope(tid) as db:
            r = db.scalar(select(ContinuousScheduleRow).where(
                ContinuousScheduleRow.schedule_id == sid,
                ContinuousScheduleRow.tenant_id == tid))
            return self._dict(r) if r else None

    def _dict(self, r):
        return {
            "schedule_id": r.schedule_id, "tenant_id": r.tenant_id,
            "target": r.target, "request": r.request,
            "interval_seconds": r.interval_seconds, "enabled": r.enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_run": r.last_run.isoformat() if r.last_run else None,
            "next_run_at": r.next_run_at.isoformat() if r.next_run_at else None,
            "last_status": r.last_status, "last_error": r.last_error,
            "lease_until": r.lease_until.isoformat() if r.lease_until else None,
        }

    def delete(self, sid):
        tid = tenant_context.get() or "legacy"
        with session_scope(tid) as db:
            r = db.scalar(select(ContinuousScheduleRow).where(
                ContinuousScheduleRow.schedule_id == sid,
                ContinuousScheduleRow.tenant_id == tid))
            if not r:
                return None
            out = self._dict(r)
            r.enabled = False
            r.lease_owner = None
            r.lease_until = None
            return out

    @staticmethod
    def enqueue_due(redis_client, owner: str, limit: int = 20) -> int:
        """Claim due schedules briefly, then enqueue durable work.

        Redis SET NX is only the cross-replica de-duplication mechanism; Postgres
        remains the source of truth for schedules and the worker lease.
        """
        now = utcnow()
        claimed = []
        db = _scheduler_db_session()
        try:
            rows = db.scalars(select(ContinuousScheduleRow).where(
                ContinuousScheduleRow.enabled == True,
                (ContinuousScheduleRow.next_run_at == None) | (ContinuousScheduleRow.next_run_at <= now),
                (ContinuousScheduleRow.lease_until == None) | (ContinuousScheduleRow.lease_until <= now)
            ).order_by(ContinuousScheduleRow.next_run_at.asc()).limit(limit)).all()
            for row in rows:
                lock_key = ENQUEUE_LOCK_PREFIX + row.schedule_id
                if not redis_client.set(lock_key, owner, nx=True, ex=LEASE_SECONDS):
                    continue
                row.next_run_at = now + timedelta(seconds=row.interval_seconds)
                row.last_status = "queued"
                claimed.append({
                    "schedule_id": row.schedule_id,
                    "tenant_id": row.tenant_id,
                    "request": row.request,
                    "target": row.target,
                })
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        for item in claimed:
            redis_client.rpush(CONTINUOUS_QUEUE, json.dumps(item, separators=(",", ":")))
        return len(claimed)

    @staticmethod
    async def execute(item: dict, worker_id: str):
        sid, tid = item["schedule_id"], item["tenant_id"]
        token = tenant_context.set(tid)
        try:
            with session_scope(tid) as db:
                row = db.scalar(select(ContinuousScheduleRow).where(
                    ContinuousScheduleRow.schedule_id == sid,
                    ContinuousScheduleRow.tenant_id == tid))
                if not row or not row.enabled:
                    return {"status": "disabled", "schedule_id": sid}
                now = utcnow()
                if row.lease_until and row.lease_until > now and row.lease_owner not in (None, worker_id):
                    return {"status": "already_running", "schedule_id": sid}
                row.lease_owner = worker_id
                row.lease_until = now + timedelta(seconds=LEASE_SECONDS)
                row.last_status = "running"
                req = FullScanRequest(**row.request)
            try:
                result = await manager.run(req)
                changes = []
                for asset in result.assets:
                    if isinstance(asset, dict):
                        changes.extend(asset.get("surface_changes", []))
                pipeline = correlate_surface_changes(
                    tenant_id=tid, result=result, changes=changes,
                    run_gemini=bool(req.run_gemini))
                with session_scope(tid) as db:
                    row = db.scalar(select(ContinuousScheduleRow).where(
                        ContinuousScheduleRow.schedule_id == sid,
                        ContinuousScheduleRow.tenant_id == tid))
                    if row:
                        row.last_run = utcnow()
                        row.last_status = "completed"
                        row.last_error = None
                        row.lease_owner = None
                        row.lease_until = None
                notify(f"Continuous scan completed: {req.target} | surface_changes={len(changes)} | incidents={pipeline['incidents']}")
                return {"status": "completed", "schedule_id": sid, "pipeline": pipeline}
            except Exception as exc:
                with session_scope(tid) as db:
                    row = db.scalar(select(ContinuousScheduleRow).where(
                        ContinuousScheduleRow.schedule_id == sid,
                        ContinuousScheduleRow.tenant_id == tid))
                    if row:
                        row.last_run = utcnow()
                        row.last_status = "failed"
                        row.last_error = str(exc)[:1000]
                        row.lease_owner = None
                        row.lease_until = None
                raise
        finally:
            tenant_context.reset(token)

continuous_scanner = ContinuousScanner()
