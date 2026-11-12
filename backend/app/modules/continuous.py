"""Durable Continuous ASM scheduling.

The API process never owns a scan coroutine. Schedules are persisted in Postgres,
due work is leased/enqueued through Redis, and the worker executes the scan.
This is safe when the API/worker fleet has multiple replicas.
"""
from __future__ import annotations

import json, uuid
from datetime import timedelta
from sqlalchemy import select
from app.core.database import ContinuousScheduleRow, BASReplayRunRow, session_scope, utcnow, engine, SessionLocal
from app.core.auth_context import tenant_context
from app.core.architecture.manager import manager
from app.core.architecture.history import UnifiedHistory
from app.core.finding_pipeline import correlate_surface_changes
from app.core.notifier import notify
from app.modules.continuous_asn import discover_new_assets_for_asn
from app.modules.attack_simulation.simulator import ReplayTarget, replay_targets, summarize_replay
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

# 4.4: used by create_bas_replay() to look up a scan's persisted findings
# (the same store /platform/history reads from) and by _execute_bas_replay()
# for nothing else - replay itself never re-reads history, it only replays.
_history = UnifiedHistory()

class ContinuousScanner:
    async def create(self, req: FullScanRequest, interval_seconds: int):
        if interval_seconds < 300:
            raise ValueError("interval_seconds must be >= 300")
        tid = tenant_context.get() or "legacy"
        sid = str(uuid.uuid4())
        now = utcnow()
        async with session_scope(tid) as db:
            db.add(ContinuousScheduleRow(
                schedule_id=sid, tenant_id=tid, target=req.target,
                request=req.model_dump(mode="json"), interval_seconds=interval_seconds,
                enabled=True, created_at=now, next_run_at=now
            ))
        return await self.get(sid, tid)

    async def create_asn_discovery(self, asn_or_org: str, interval_seconds: int) -> dict:
        """3.1: schedule recurring organization-wide asset discovery instead
        of re-scanning one known target. Stored in the SAME
        ContinuousScheduleRow.request JSON column as an ordinary schedule -
        distinguished only by the "__kind__" sentinel key, which execute()
        checks BEFORE attempting `FullScanRequest(**row.request)` (a plain
        asn_discovery payload is deliberately not a valid FullScanRequest,
        so that reconstruction must never be reached for this kind). This
        avoids a schema migration: `known_assets` (the diff baseline) lives
        in the same JSON blob and is updated in place after every run.
        """
        if interval_seconds < 300:
            raise ValueError("interval_seconds must be >= 300")
        tid = tenant_context.get() or "legacy"
        sid = str(uuid.uuid4())
        now = utcnow()
        async with session_scope(tid) as db:
            db.add(ContinuousScheduleRow(
                schedule_id=sid, tenant_id=tid, target=asn_or_org,
                request={"__kind__": "asn_discovery", "asn_or_org": asn_or_org, "known_assets": []},
                interval_seconds=interval_seconds, enabled=True, created_at=now, next_run_at=now,
            ))
        return await self.get(sid, tid)

    async def create_bas_replay(self, scan_id: str, finding_ids: list[str], interval_seconds: int) -> dict:
        """4.4: schedule recurring safe replay of already-detected
        template-backed findings from one scan, to confirm they are still
        live (or flag that they've been resolved) - see
        attack_simulation/simulator.py for what "replay" actually does.

        Only findings that are template-backed (tagged "template" - see
        normalizer.py's web.template_findings handling) and still carry a
        rule_id/affected_asset are replayable; anything else in
        finding_ids is silently skipped rather than raising, since a mixed
        selection (e.g. a template finding alongside a TLS finding) is a
        normal thing for a caller to send.
        """
        if interval_seconds < 300:
            raise ValueError("interval_seconds must be >= 300")
        scan = await _history.get(scan_id)
        if not scan:
            raise ValueError(f"scan not found: {scan_id}")
        wanted = set(finding_ids)
        targets: list[dict] = []
        for f in getattr(scan, "findings", None) or (scan.get("findings") if isinstance(scan, dict) else []) or []:
            fid = f.get("finding_id") if isinstance(f, dict) else getattr(f, "finding_id", None)
            if fid not in wanted:
                continue
            tags = f.get("tags") if isinstance(f, dict) else getattr(f, "tags", [])
            rule_id = f.get("rule_id") if isinstance(f, dict) else getattr(f, "rule_id", None)
            asset = f.get("affected_asset") if isinstance(f, dict) else getattr(f, "affected_asset", None)
            if "template" not in (tags or []) or not rule_id or not asset:
                continue
            targets.append({"finding_id": fid, "template_id": rule_id, "url": asset, "method": "GET"})
        if not targets:
            raise ValueError("no replayable (template-backed) findings among the given finding_ids")

        tid = tenant_context.get() or "legacy"
        sid = str(uuid.uuid4())
        now = utcnow()
        async with session_scope(tid) as db:
            db.add(ContinuousScheduleRow(
                schedule_id=sid, tenant_id=tid, target=f"bas-replay:{scan_id}",
                request={"__kind__": "bas_replay", "scan_id": scan_id, "targets": targets},
                interval_seconds=interval_seconds, enabled=True, created_at=now, next_run_at=now,
            ))
        return await self.get(sid, tid)

    async def list(self):
        tid = tenant_context.get() or "legacy"
        async with session_scope(tid) as db:
            return [self._dict(r) for r in (await db.scalars(
                select(ContinuousScheduleRow)
                .where(ContinuousScheduleRow.tenant_id == tid)
                .order_by(ContinuousScheduleRow.created_at.desc())
            )).all()]

    async def list_all(self):
        async with session_scope("legacy") as db:
            return [self._dict(r) for r in (await db.scalars(
                select(ContinuousScheduleRow)
                .where(ContinuousScheduleRow.enabled == True)
            )).all()]

    async def get(self, sid, tid):
        async with session_scope(tid) as db:
            r = await db.scalar(select(ContinuousScheduleRow).where(
                ContinuousScheduleRow.schedule_id == sid,
                ContinuousScheduleRow.tenant_id == tid))
            return self._dict(r) if r else None

    def _dict(self, r):
        return {
            "schedule_id": r.schedule_id, "tenant_id": r.tenant_id,
            "target": r.target, "request": r.request,
            "schedule_kind": (r.request or {}).get("__kind__", "target_rescan"),
            "interval_seconds": r.interval_seconds, "enabled": r.enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_run": r.last_run.isoformat() if r.last_run else None,
            "next_run_at": r.next_run_at.isoformat() if r.next_run_at else None,
            "last_status": r.last_status, "last_error": r.last_error,
            "lease_until": r.lease_until.isoformat() if r.lease_until else None,
        }

    async def delete(self, sid):
        tid = tenant_context.get() or "legacy"
        async with session_scope(tid) as db:
            r = await db.scalar(select(ContinuousScheduleRow).where(
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
        # In local/test SQLite deployments the scheduler must share the primary
        # database engine. A separately-created PostgreSQL engine here can point
        # at a stale/default URL and break durable scheduling before Redis is used.
        if engine.dialect.name == "sqlite":
            # enqueue_due() is deliberately synchronous (see its docstring:
            # isolated from the async request-serving engine so a multi-
            # replica scheduler loop never contends with it) - it cannot use
            # the async session_scope() above, so it goes through the sync
            # SessionLocal directly here, same as _scheduler_db_session()
            # does for the Postgres branch just below.
            db = SessionLocal()
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
                    claimed.append({"schedule_id": row.schedule_id, "tenant_id": row.tenant_id, "request": row.request, "target": row.target})
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        else:
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
                    claimed.append({"schedule_id": row.schedule_id, "tenant_id": row.tenant_id, "request": row.request, "target": row.target})
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
            async with session_scope(tid) as db:
                row = await db.scalar(select(ContinuousScheduleRow).where(
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
                # 3.1/4.4: asn_discovery/bas_replay schedules carry a payload
                # that is NOT a valid FullScanRequest (see
                # create_asn_discovery/create_bas_replay above) - this check
                # must happen before FullScanRequest(**row.request) is ever
                # attempted, not after it fails.
                schedule_kind = (row.request or {}).get("__kind__", "target_rescan")
                if schedule_kind == "asn_discovery":
                    asn_or_org = row.request.get("asn_or_org", row.target)
                    known_assets = set(row.request.get("known_assets", []))
                elif schedule_kind == "bas_replay":
                    bas_scan_id = row.request.get("scan_id", "")
                    bas_targets = row.request.get("targets", [])
                else:
                    req = FullScanRequest(**row.request)

            if schedule_kind == "asn_discovery":
                return await ContinuousScanner._execute_asn_discovery(sid, tid, asn_or_org, known_assets)
            if schedule_kind == "bas_replay":
                return await ContinuousScanner._execute_bas_replay(sid, tid, bas_scan_id, bas_targets)

            try:
                result = await manager.run(req)
                changes = []
                for asset in result.assets:
                    if isinstance(asset, dict):
                        changes.extend(asset.get("surface_changes", []))
                pipeline = await correlate_surface_changes(
                    tenant_id=tid, result=result, changes=changes,
                    run_gemini=bool(req.run_gemini))
                async with session_scope(tid) as db:
                    row = await db.scalar(select(ContinuousScheduleRow).where(
                        ContinuousScheduleRow.schedule_id == sid,
                        ContinuousScheduleRow.tenant_id == tid))
                    if row:
                        row.last_run = utcnow()
                        row.last_status = "completed"
                        row.last_error = None
                        row.lease_owner = None
                        row.lease_until = None
                notify(
                    f"Continuous scan completed: {req.target} | surface_changes={len(changes)} | incidents={pipeline['incidents']}",
                    event={
                        "name": "continuous-scan-completed",
                        "severity": "High" if pipeline.get("incidents", 0) > 0 else "Info",
                        "target": req.target,
                        "scan_id": getattr(result, "scan_id", None),
                        "finding_count": len(getattr(result, "findings", []) or []),
                    },
                )
                return {"status": "completed", "schedule_id": sid, "pipeline": pipeline}
            except Exception as exc:
                async with session_scope(tid) as db:
                    row = await db.scalar(select(ContinuousScheduleRow).where(
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

    @staticmethod
    async def _execute_asn_discovery(sid: str, tid: str, asn_or_org: str, known_assets: set[str]) -> dict:
        """3.1 execution path for schedule_kind == "asn_discovery". Mirrors
        execute()'s lease-release/last_run/last_status bookkeeping so a
        discovery schedule behaves identically to a rescan schedule from the
        scheduler's point of view (same statuses, same lease semantics) -
        only the work performed in between differs.

        Does NOT set/reset tenant_context itself - the caller (execute())
        already holds it set for the duration of the whole call; doing it
        again here would reset a contextvars.Token that was never issued by
        this nested call, which contextvars raises on.
        """
        try:
            new_targets = await discover_new_assets_for_asn(asn_or_org, already_scanned=known_assets)
            async with session_scope(tid) as db:
                row = await db.scalar(select(ContinuousScheduleRow).where(
                    ContinuousScheduleRow.schedule_id == sid,
                    ContinuousScheduleRow.tenant_id == tid))
                if row:
                    row.last_run = utcnow()
                    row.last_status = "completed"
                    row.last_error = None
                    row.lease_owner = None
                    row.lease_until = None
                    # New dict assignment (not in-place mutation) so the
                    # ORM's change-tracking on the JSON column fires.
                    row.request = {
                        "__kind__": "asn_discovery",
                        "asn_or_org": asn_or_org,
                        "known_assets": sorted(known_assets | set(new_targets)),
                    }
            if new_targets:
                notify(
                    f"ASN discovery found {len(new_targets)} new asset(s) under {asn_or_org}: {', '.join(new_targets[:10])}"
                    + (" ..." if len(new_targets) > 10 else ""),
                    event={
                        "name": "asn-discovery-new-assets",
                        "severity": "Medium",
                        "target": asn_or_org,
                        "scan_id": sid,
                        "finding_count": len(new_targets),
                    },
                )
            return {"status": "completed", "schedule_id": sid, "new_assets": new_targets}
        except Exception as exc:
            async with session_scope(tid) as db:
                row = await db.scalar(select(ContinuousScheduleRow).where(
                    ContinuousScheduleRow.schedule_id == sid,
                    ContinuousScheduleRow.tenant_id == tid))
                if row:
                    row.last_run = utcnow()
                    row.last_status = "failed"
                    row.last_error = str(exc)[:1000]
                    row.lease_owner = None
                    row.lease_until = None
            raise

    @staticmethod
    async def _execute_bas_replay(sid: str, tid: str, scan_id: str, targets: list[dict]) -> dict:
        """4.4 execution path for schedule_kind == "bas_replay". Same
        lease/last_run/last_status bookkeeping as _execute_asn_discovery,
        so BAS schedules behave identically to any other schedule kind from
        the scheduler's point of view."""
        try:
            replay_outcomes = await replay_targets([ReplayTarget(**t) for t in targets])
            summary = summarize_replay(replay_outcomes)
            async with session_scope(tid) as db:
                row = await db.scalar(select(ContinuousScheduleRow).where(
                    ContinuousScheduleRow.schedule_id == sid,
                    ContinuousScheduleRow.tenant_id == tid))
                if row:
                    row.last_run = utcnow()
                    row.last_status = "completed"
                    row.last_error = None
                    row.lease_owner = None
                    row.lease_until = None
                    row.request = {
                        "__kind__": "bas_replay",
                        "scan_id": scan_id,
                        "targets": targets,
                        "last_summary": {
                            "total_targets": summary.total_targets,
                            "still_live_count": summary.still_live_count,
                            "resolved_count": summary.resolved_count,
                            "unknown_count": summary.unknown_count,
                            "checked_at": replay_outcomes[0].checked_at if replay_outcomes else None,
                        },
                    }
                # Durable history row (0016_bas_replay_history.sql), separate
                # from the cache above: that JSON blob only ever holds the
                # latest run, this table keeps every run so trend/audit
                # queries don't depend on catching the schedule row before
                # the next replay overwrites it.
                db.add(BASReplayRunRow(
                    id=str(uuid.uuid4()), tenant_id=tid, schedule_id=sid, scan_id=scan_id,
                    total_targets=summary.total_targets, still_live_count=summary.still_live_count,
                    resolved_count=summary.resolved_count, unknown_count=summary.unknown_count,
                    outcomes=[o.__dict__ for o in replay_outcomes],
                ))
            # Per the module's own design note: only alert when the finding
            # set is confirmed FULLY still live (no partial resolution) -
            # a mixed or fully-resolved result is progress, not an incident,
            # and paging on it would train people to ignore BAS alerts.
            if summary.still_live_count and summary.resolved_count == 0:
                notify(
                    f"BAS replay: {summary.still_live_count}/{summary.total_targets} finding(s) from scan {scan_id} are still exploitable.",
                    event={
                        "name": "bas-replay-still-live",
                        "severity": "High",
                        "target": scan_id,
                        "scan_id": sid,
                        "finding_count": summary.still_live_count,
                    },
                )
            elif summary.resolved_count:
                notify(
                    f"BAS replay: {summary.resolved_count}/{summary.total_targets} finding(s) from scan {scan_id} no longer reproduce (likely remediated).",
                    event={"name": "bas-replay-resolved", "severity": "Info", "target": scan_id, "scan_id": sid, "finding_count": summary.resolved_count},
                )
            return {"status": "completed", "schedule_id": sid, "summary": {
                "still_live": summary.still_live_count, "resolved": summary.resolved_count, "unknown": summary.unknown_count,
            }}
        except Exception as exc:
            async with session_scope(tid) as db:
                row = await db.scalar(select(ContinuousScheduleRow).where(
                    ContinuousScheduleRow.schedule_id == sid,
                    ContinuousScheduleRow.tenant_id == tid))
                if row:
                    row.last_run = utcnow()
                    row.last_status = "failed"
                    row.last_error = str(exc)[:1000]
                    row.lease_owner = None
                    row.lease_until = None
            raise

continuous_scanner = ContinuousScanner()
