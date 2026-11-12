from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import queue
import threading
import time
import uuid
from concurrent.futures import Future
from typing import Any, Awaitable, Callable
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import defer

from app.core.config import settings
from app.core.database import JobRow, ScanRow, ScanExecutionRow, ScanExecutionEventRow, init_db_with_retry, jsonable, session_scope_sync, utcnow, with_db_retry
from app.core.auth_context import tenant_context
from app.core.auth import current_principal_optional
from app.core.policy_enforcement import scan_policy, scan_timeout_seconds
from app.core.job_payload_crypto import protect_job_payload, restore_job_payload
from app.schemas.jobs import JobSnapshot, JobStatus

logger = logging.getLogger(__name__)

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None


_HOT_CACHE_TTL_SECONDS = 60 * 60 * 24
_hot_cache_client = None
_hot_cache_disabled_until = 0.0

def _hot_cache():
    """Best-effort Redis cache for the tiny, frequently changing job snapshot.

    The database remains the source of truth. Redis is only the hot read path so
    the API/WebSocket never has to hit Supabase/Postgres every 500ms while a scan
    is running. A cache miss always falls back to the durable row.
    """
    global _hot_cache_client, _hot_cache_disabled_until
    if redis is None or not settings.REDIS_URL:
        return None
    if _hot_cache_client is None:
        _hot_cache_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True,
            socket_connect_timeout=1, socket_timeout=1, health_check_interval=30)
    return _hot_cache_client

def _hot_key(tenant_id: str, job_id: str) -> str:
    return f"mirsad:job:hot:{tenant_id}:{job_id}"

# Live (partial) raw engine result. It can reach hundreds of KB and changes every few
# seconds during a scan. Keeping it inside scan_jobs.payload made every progress/stage/log
# write and every poll re-read it from Postgres (Supabase egress). While Redis is healthy
# it now lives ONLY in Redis and is flushed to the durable row once, when the job reaches a
# terminal state. Without Redis the previous DB-only behaviour is kept.
_LIVE_TTL_SECONDS = 60 * 60 * 24 * 7
_live_last_db_write: dict[str, float] = {}

def _live_key(tenant_id: str, job_id: str) -> str:
    return f"mirsad:job:live:{tenant_id}:{job_id}"

def read_live_result_cached(tenant_id: str, job_id: str) -> dict | None:
    """Return the live result stored in Redis, or None (missing / Redis unavailable)."""
    if time.monotonic() < _hot_cache_disabled_until:
        return None
    try:
        r = _hot_cache()
        if r is None:
            return None
        raw = r.get(_live_key(tenant_id, job_id))
        data = json.loads(raw) if raw else None
        return data if isinstance(data, dict) and data else None
    except Exception:
        logger.debug("live-result Redis read failed for %s", job_id, exc_info=True)
        return None

SENSITIVE_EXECUTION_FIELDS = {
    "login_username", "login_password", "auth_header", "cookie",
    "authorized_auth_header", "authorized_cookie", "unauthorized_auth_header",
    "unauthorized_cookie",
}

def _safe_execution_config(payload: dict | None) -> dict:
    """Return only non-sensitive persisted configuration; never decrypt credentials."""
    source = dict(payload or {})
    out = {}
    for key, value in source.items():
        if str(key).startswith("_"):
            continue
        if key in SENSITIVE_EXECUTION_FIELDS:
            out[key] = "••••" if value not in (None, "", [], {}) else ""
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            out[key] = [str(x)[:2048] for x in value[:500]]
        elif isinstance(value, dict):
            out[key] = {str(k): str(v)[:2048] for k, v in list(value.items())[:200]}
    return out

def datetime_from_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z","+00:00"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Ordered background DB writer
#
# 2026-10-11: JobRecord used to run every progress/log/stage/event write as a
# *synchronous* psycopg2 transaction directly on the asyncio event-loop thread
# of the worker. Against a remote Supabase pooler each of those writes is one or
# more WAN round-trips, and a single scan emits thousands of them. Whenever the
# link slowed down (or the host was busy with nmap/ZAP/SQLMap) the whole event
# loop froze: heartbeats stopped, the stall watchdog reported
# ``event_loop_blocked`` (lag 57-64s), pool waits timed out and the job ended
# with ``Worker failed: `` (an empty TimeoutError).
#
# Non-critical, append-style writes (log lines, stage/progress updates, engine
# events, heartbeats, partial results) now go through ONE background thread:
#   * strictly FIFO, so ordering is exactly what the inline code produced;
#   * the caller's contextvars (tenant context) are copied to the thread;
#   * failures are logged and never raised into the scan;
#   * writes that decide job state (status / error / result / execution
#     start-finish) still wait for completion, and, being FIFO, they also wait
#     for every earlier queued write first, so nothing is reordered or lost.
# Set MIRSAD_JOB_BACKGROUND_WRITES=0 to restore the previous fully-inline behaviour.
# ---------------------------------------------------------------------------
_BG_WRITES_ENABLED = os.environ.get("MIRSAD_JOB_BACKGROUND_WRITES", "1").strip().lower() not in {"0", "false", "no", "off"}
_BG_MAX_PENDING = 5000


class _OrderedDbWriter:
    def __init__(self):
        self._q: "queue.Queue" = queue.Queue()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._pending_keys: set = set()
        self._pending_by_job: dict[str, int] = {}

    def _ensure_thread(self):
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="mirsad-job-writer", daemon=True)
                self._thread.start()

    def _run(self):
        while True:
            fn, ctx, fut, key, job_id = self._q.get()
            try:
                if key is not None:
                    with self._lock:
                        self._pending_keys.discard(key)
                result = ctx.run(fn)
                if fut is not None:
                    fut.set_result(result)
            except Exception as exc:
                if fut is not None:
                    fut.set_exception(exc)
                else:
                    logger.warning("background job write failed for %s: %s: %s", job_id, type(exc).__name__, exc or "(no message)", exc_info=True)
            finally:
                if job_id is not None:
                    with self._lock:
                        left = self._pending_by_job.get(job_id, 1) - 1
                        if left <= 0:
                            self._pending_by_job.pop(job_id, None)
                        else:
                            self._pending_by_job[job_id] = left
                self._q.task_done()

    def pending(self, job_id: str) -> bool:
        with self._lock:
            return self._pending_by_job.get(job_id, 0) > 0

    def submit(self, fn, *, job_id: str | None = None, wait: bool, key=None):
        """Queue ``fn``. ``wait=True`` blocks for its result (raising its exception)."""
        self._ensure_thread()
        ctx = contextvars.copy_context()
        if not wait and self._q.qsize() >= _BG_MAX_PENDING:
            wait = True  # natural back-pressure: behave like the old inline write
        fut: Future | None = Future() if wait else None
        if not wait and key is not None:
            with self._lock:
                if key in self._pending_keys:
                    return None  # an identical write is already queued (heartbeat coalescing)
                self._pending_keys.add(key)
        if job_id is not None:
            with self._lock:
                self._pending_by_job[job_id] = self._pending_by_job.get(job_id, 0) + 1
        self._q.put((fn, ctx, fut, key, job_id))
        return fut.result() if fut is not None else None

    def flush(self, timeout: float | None = 60.0) -> bool:
        """Block until everything queued so far has been attempted."""
        self._ensure_thread()
        fut: Future = Future()
        self._q.put((lambda: None, contextvars.copy_context(), fut, None, None))
        try:
            fut.result(timeout=timeout)
            return True
        except Exception:
            return False


_writer = _OrderedDbWriter()


def _in_running_loop() -> bool:
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


_TERMINAL_JOB_STATUSES = {"completed", "partial", "failed", "cancelled"}


def _owned_row(db, job_id, *, defer_result: bool = False, defer_payload: bool = False):
    """Load the job row visible to the current tenant.

    ``defer_result`` / ``defer_payload`` skip the two heavy JSON columns
    (result ~190KB, payload ~330KB incl. live progress/result). Callers that
    only need status/progress/error must pass them: every full-row load is DB->app
    traffic and was the main Supabase egress source. A deferred column must NOT be
    read after the session closes (it would raise DetachedInstanceError).
    """
    opts=[]
    if defer_result: opts.append(defer(JobRow.result))
    if defer_payload: opts.append(defer(JobRow.payload))
    row=db.get(JobRow, job_id, options=opts) if opts else db.get(JobRow, job_id)
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


# Conservative stage-duration priors (seconds). ETA is stage-aware rather than
# derived from raw overall percentage, so long tools such as ZAP/ffuf do not
# make the estimate jump wildly.
_STAGE_PRIORS = {
    "target_validation": 2.0, "target_reachability": 3.0, "dns_lookup": 6.0, "port_scan": 20.0, "service_discovery": 10.0,
    "web_crawl": 120.0, "api_security": 60.0, "source_intelligence": 35.0,
    "external_scanners": 90.0, "subdomain_discovery": 20.0, "subdomain_dns": 12.0,
    "subdomain_network": 35.0, "subdomain_web": 90.0, "subdomain_api": 60.0,
    "advanced_security": 900.0, "vulnerability_analysis": 25.0, "risk_correlation": 12.0, "ai_validation": 18.0,
    "finalize": 6.0,
}

def _stage_eta(stages: list[dict], now: datetime) -> tuple[float | None, float | None]:
    if not stages:
        return None, None
    durations = []
    for s in stages:
        if s.get("status") == "completed" and s.get("started_at") and s.get("finished_at"):
            try:
                a = datetime_from_iso(s["started_at"]); b = datetime_from_iso(s["finished_at"])
                if a and b:
                    durations.append(max(1.0, (b-a).total_seconds()))
            except Exception:
                logger.debug("suppressed non-fatal error", exc_info=True)
    median = sorted(durations)[len(durations)//2] if durations else 30.0
    total = 0.0
    current = None
    for s in stages:
        status = str(s.get("status") or "pending")
        if status in {"completed", "failed", "skipped"}:
            continue
        sid = str(s.get("id") or "")
        if sid.startswith("external_") and sid != "external_scanners":
            # Per-tool child stages run inside (and in parallel under) the
            # parent `external_scanners` stage, whose hint already covers them;
            # adding them again inflated the total ETA to many hours.
            continue
        prior = float(s.get("eta_hint_seconds") or _STAGE_PRIORS.get(sid, median))
        if status == "running":
            pct = max(0.0, min(100.0, float(s.get("progress") or 0)))
            started = datetime_from_iso(s.get("started_at")) if s.get("started_at") else None
            observed = max(0.0, (now-started).total_seconds()) if started else 0.0
            if sid == "external_scanners":
                # external_scanners stores eta_hint_seconds as the sum of the
                # configured timeouts for tools that are still pending; do not
                # apply progress a second time.
                remaining_prior = max(0.0, prior)
                if pct >= 5 and observed > 2:
                    observed_total = observed / max(pct/100.0, 0.01)
                    raw_rem = max(remaining_prior, observed_total-observed)
                else:
                    raw_rem = remaining_prior
                raw_rem = max(raw_rem, observed * 0.25 if observed else 0.0)
            elif pct >= 5 and observed > 2:
                observed_total = observed / (pct/100.0)
                estimate = max(prior, observed_total)
                raw_rem = max(estimate * (1-pct/100.0), observed * 0.25)
            else:
                raw_rem = max(prior * (1-pct/100.0), observed * 0.25 if observed else 0.0)
            previous = s.get("eta_ema_seconds")
            try:
                previous = float(previous) if previous is not None else None
            except Exception:
                previous = None
            ema = raw_rem if previous is None else (0.7 * previous + 0.3 * raw_rem)
            if observed > 0:
                ema = max(ema, observed * 0.25)
            s["eta_ema_seconds"] = ema
            current = max(ema, 1.0)
            total += current
        else:
            total += prior
    return total, current

_TERMINAL_STAGE_STATES = ("completed", "partial", "failed", "skipped")


def _apply_task_counts(meta: dict, stages: list) -> None:
    """completed_tasks = every stage that reached a terminal state.

    Previously only status == "completed" was counted, so a finished scan with
    skipped/partial/failed stages showed e.g. 18/27 at 100%. The per-state
    breakdown is kept in task_breakdown so nothing is hidden.
    """
    breakdown = {k: 0 for k in ("completed", "partial", "failed", "skipped", "running", "pending")}
    for x in stages:
        st = str(x.get("status") or "pending")
        breakdown[st] = breakdown.get(st, 0) + 1
    meta["task_breakdown"] = breakdown
    meta["completed_tasks"] = sum(breakdown.get(k, 0) for k in _TERMINAL_STAGE_STATES)


class JobRecord:
    """DB-backed job handle. Mutations are immediately durable."""
    def __init__(self, job_id: str, job_type: str, target: str, task: asyncio.Task | None = None):
        self.job_id, self.job_type, self.target, self.task = job_id, job_type, target, task
        self.pause_event = asyncio.Event(); self.pause_event.set()
        self.execution_id: str | None = None
        self.tenant_id: str | None = None

    def _ensure_execution_id(self) -> str | None:
        if self.execution_id: return self.execution_id
        row = self._row(defer_result=True)
        if not row: return None
        self.execution_id = (row.payload or {}).get('_execution_id')
        return self.execution_id

    def start_execution(self, started_at=None, count_attempt: bool = True) -> str | None:
        """Create the scan_executions row and bind event tracing to it.

        Shared by JobManager._execute and the Redis worker. The worker path
        used to skip this entirely, so job.execution_id stayed None and every
        live event / HTTP trace was dropped (empty events page, 0 counters).
        """
        from app.core.execution_trace import empty_stats as _empty_stats
        started_at = started_at or utcnow()
        execution_id = uuid.uuid4().hex
        self.tenant_id = tenant_context.get() or "legacy"
        created = {"ok": False}
        def _start_execution():
            with session_scope_sync() as db:
                row = _owned_row(db, self.job_id)
                if not row:
                    logger.error("scan_executions row NOT created for job %s: job not visible under tenant context %r", self.job_id, tenant_context.get())
                    return
                # The Redis worker already counted this attempt in worker._load (count_attempt=False);
                # counting it again made every finalize look like a stale attempt and get skipped.
                attempt_no = int(row.attempt_count or 0) + (1 if count_attempt else 0)
                row.attempt_count = attempt_no
                payload = dict(row.payload or {})
                payload['_execution_id'] = execution_id
                row.payload = payload
                db.add(ScanExecutionRow(
                    execution_id=execution_id, tenant_id=row.tenant_id, scan_id=row.job_id, job_id=row.job_id,
                    attempt=attempt_no, job_type=row.job_type, target=row.target, status=JobStatus.RUNNING.value,
                    current_engine=row.current_engine, meta={'job_type': row.job_type, 'target': row.target, 'stats': _empty_stats()}, started_at=started_at))
                created["ok"] = True
        with_db_retry(_start_execution)
        if not created["ok"]:
            self.execution_id = None
            return None
        self.execution_id = execution_id
        from app.core import execution_trace as _trace
        _trace.bind_job(self)
        row = self._row()
        self.record_event('execution_started', message='Execution started', payload={'attempt': (row.attempt_count if row else 1)}, background=False)
        return execution_id

    def finish_execution(self, finished_at=None) -> None:
        """Mark the execution row finished and flush queued trace events."""
        execution_id = self.execution_id
        if not execution_id:
            return
        finished_at = finished_at or utcnow()
        def _fin():
            with session_scope_sync() as db:
                exec_row = db.get(ScanExecutionRow, execution_id)
                if exec_row:
                    exec_row.status = self.status.value
                    exec_row.current_engine = self.current_engine
                    exec_row.finished_at = finished_at
        try:
            with_db_retry(_fin)
        except Exception:
            logger.warning("could not finalize scan_executions row %s", execution_id, exc_info=True)
        try:
            from app.core import execution_trace as _trace
            _trace.flush()
            _trace.forget(execution_id)
        except Exception:
            logger.debug('trace flush failed', exc_info=True)
        self.record_event('execution_finished', message=f'Execution {self.status.value}', payload={'status': self.status.value}, background=False)

    def record_event(self, event_type: str, *, message: str = '', stage: str | None = None, tool: str | None = None,
                     operation_id: str | None = None, payload: dict | None = None, background: bool = True):
        """Append an immutable event to the current execution stream.

        The event is tenant + scan + execution scoped, so parallel workers can
        never be merged merely because they share a scan/job. Sequence numbers
        are allocated transactionally per execution.
        """
        execution_id = self._ensure_execution_id()
        if not execution_id: return
        # Snapshot the payload now: when the write is queued the caller's dict
        # may be mutated before the background thread gets to it.
        ev_payload = jsonable(payload or {})
        ev_created_at = utcnow()
        def _txn():
            with session_scope_sync() as db:
                row = _owned_row(db, self.job_id)
                if not row: return
                execution = db.execute(select(ScanExecutionRow).where(
                    ScanExecutionRow.execution_id == execution_id,
                    ScanExecutionRow.tenant_id == row.tenant_id
                ).with_for_update()).scalar_one_or_none()
                if not execution:
                    logger.warning('execution event %s dropped: no scan_executions row for %s', event_type, execution_id)
                    return
                last = db.execute(select(func.max(ScanExecutionEventRow.sequence)).where(
                    ScanExecutionEventRow.tenant_id == row.tenant_id,
                    ScanExecutionEventRow.execution_id == execution_id
                )).scalar_one() or 0
                ev_stage = (stage or row.current_engine or '')[:128] or None
                db.add(ScanExecutionEventRow(
                    event_id=uuid.uuid4().hex, tenant_id=row.tenant_id, scan_id=row.job_id,
                    execution_id=execution_id, operation_id=operation_id, sequence=int(last)+1,
                    event_type=event_type[:64], stage=ev_stage,
                    tool=(tool or row.current_engine or '')[:128] or None, message=str(message)[:4000],
                    payload=ev_payload, created_at=ev_created_at))
                from app.core.execution_trace import add_events_to_meta
                add_events_to_meta(execution, [(event_type[:64], ev_stage, ev_payload, int(last)+1)])
        use_bg = background and _BG_WRITES_ENABLED and _in_running_loop()
        try: _writer.submit(lambda: with_db_retry(_txn), job_id=self.job_id, wait=not use_bg)
        except Exception: logger.warning('execution event persistence failed for %s', self.job_id, exc_info=True)

    def flush_writes(self, timeout: float | None = 60.0) -> bool:
        """Wait until every queued background write has been attempted."""
        return _writer.flush(timeout)


    def publish_partial_result(self, *, network=None, web=None, api=None, extra=None):
        """Persist a lightweight raw engine snapshot while the scan is running.

        Redis is the primary store while the job runs (see read_live_result_cached);
        the durable row only gets it when Redis is unavailable, every
        LIVE_RESULT_DB_MIN_INTERVAL_SECONDS (when > 0), and once at the terminal state.
        """
        # Serialize now (the engines keep mutating these objects), write later.
        prepared = {key: jsonable(value) for key, value in (("network_scan", network), ("web_scan", web), ("api_scan", api)) if value is not None}
        prepared_extra = jsonable(extra) if extra else None
        tenant = tenant_context.get() or "legacy"
        job_id = self.job_id

        def _merge(existing):
            live = dict(existing or {})
            live.update(prepared)
            if prepared_extra:
                live.update(prepared_extra)
            live["updated_at"] = utcnow().isoformat()
            return live

        def _mutate(row):
            payload = dict(row.payload or {})
            payload["_live_result"] = _merge(payload.get("_live_result"))
            row.payload = payload

        def _run():
            global _hot_cache_disabled_until
            live = None
            r = None if time.monotonic() < _hot_cache_disabled_until else _hot_cache()
            if r is not None:
                try:
                    raw = r.get(_live_key(tenant, job_id))
                    live = _merge(json.loads(raw) if raw else None)
                    r.setex(_live_key(tenant, job_id), _LIVE_TTL_SECONDS, json.dumps(live, separators=(",", ":"), default=str))
                except Exception:
                    live = None
                    _hot_cache_disabled_until = time.monotonic() + 30
            if live is None:
                self._write_now(_mutate)  # Redis unavailable: durable row only (previous behaviour)
                return
            from app.core.stall_watchdog import touch
            touch(job_id)
            interval = int(getattr(settings, "LIVE_RESULT_DB_MIN_INTERVAL_SECONDS", 0) or 0)
            now = time.monotonic()
            if interval > 0 and now - _live_last_db_write.get(job_id, 0.0) >= interval:
                _live_last_db_write[job_id] = now
                def _store(row, _live=live):
                    payload = dict(row.payload or {})
                    payload["_live_result"] = _live
                    row.payload = payload
                self._write_now(_store, cache=False, activity=False)
        try:
            use_bg = _BG_WRITES_ENABLED and _in_running_loop()
            _writer.submit(_run, job_id=job_id, wait=not use_bg)
        except Exception:
            logger.debug("partial result persistence failed for %s", self.job_id, exc_info=True)

    def _flush_live_to_row(self, row):
        """Called inside the terminal status write: copy the Redis live result into the durable row."""
        live = read_live_result_cached(row.tenant_id, self.job_id)
        _live_last_db_write.pop(self.job_id, None)
        if live:
            payload = dict(row.payload or {})
            payload["_live_result"] = live
            row.payload = payload

    def _row(self, consistent: bool = True, *, defer_result: bool = False, defer_payload: bool = False):
        # Read-your-writes: if this job still has queued background writes,
        # let them land first so callers never observe a stale row.
        if consistent and _BG_WRITES_ENABLED and _writer.pending(self.job_id):
            _writer.flush(60.0)
        def _read():
            with session_scope_sync() as db:
                row=_owned_row(db, self.job_id, defer_result=defer_result, defer_payload=defer_payload)
                tid=tenant_context.get()
                if row and tid and row.tenant_id != tid: return None
                return row
        return with_db_retry(_read)

    def _status_only(self):
        """Fetch ONLY the status column. The control loop polls this every few seconds per
        running job; loading the whole row (payload up to ~330KB + result up to ~190KB) each time
        was the main source of the Supabase egress overage (10.8GB of 5GB, 2026-10)."""
        def _read():
            with session_scope_sync() as db:
                tid=tenant_context.get()
                q=select(JobRow.status, JobRow.tenant_id).where(JobRow.job_id==self.job_id)
                rec=db.execute(q).first()
                if not rec: return None
                if tid is None:
                    return rec[0] if rec[1]=="legacy" else None  # fail closed, same rule as _owned_row
                return rec[0] if rec[1]==tid else None
        return with_db_retry(_read)

    def _result_only(self):
        """Fetch ONLY the final result column (used for terminal snapshots)."""
        def _read():
            with session_scope_sync() as db:
                tid=tenant_context.get()
                rec=db.execute(select(JobRow.result, JobRow.tenant_id).where(JobRow.job_id==self.job_id)).first()
                if not rec: return None
                if tid is None:
                    return rec[0] if rec[1]=="legacy" else None
                return rec[0] if rec[1]==tid else None
        return with_db_retry(_read)

    def _write(self, mutate, *, cache: bool = True, activity: bool = True, background: bool = False, key=None):
        """Run ``mutate(row)`` against this job's row in a durable, retried transaction.

        2026-09-15: every setter below used to open its own bare
        ``with session_scope_sync() as db:`` with zero retry. A single transient
        Supabase/Postgres disconnect mid-write (SSL EOF — see with_db_retry's
        docstring in app/core/database.py) would silently drop that one
        progress update while the scan itself kept running unaffected,
        leaving the persisted job row a step behind reality until the next
        successful write caught it back up.
        """
        self._submit_write(self._make_write_run(mutate, cache, activity), background=background, key=key)

    def _make_write_run(self, mutate, cache: bool, activity: bool):
        def _txn():
            with session_scope_sync() as db:
                # The old `result` is never read by any mutator (the setter only overwrites it).
                row=_owned_row(db, self.job_id, defer_result=True)
                if row:
                    mutate(row)
                    if cache: self._cache_snapshot(row)
        def _run():
            with_db_retry(_txn)
            if activity:
                # Real progress for the stall watchdog (app/core/stall_watchdog.py).
                # Heartbeats pass activity=False so a frozen scan cannot look alive.
                # Touched only after the write really succeeded.
                from app.core.stall_watchdog import touch
                touch(self.job_id)
        return _run

    def _write_now(self, mutate, *, cache: bool = True, activity: bool = True):
        """Run the write inline (used from inside the writer thread; never re-queues)."""
        self._make_write_run(mutate, cache, activity)()

    def _submit_write(self, _run, *, background: bool, key=None):
        # background=True: queued on the ordered writer thread, the event loop is
        # not blocked and a DB failure is logged instead of raised into the scan.
        # Otherwise the call waits (FIFO behind any queued writes) and raises.
        use_bg = background and _BG_WRITES_ENABLED and _in_running_loop()
        _writer.submit(_run, job_id=self.job_id, wait=not use_bg, key=key)

    @property
    def status(self) -> JobStatus:
        # Test doubles created with object.__new__ do not have a durable job_id.
        # Keep the normal DB-backed path untouched while allowing close_open_stages
        # to be exercised without a database row.
        if not hasattr(self, "job_id"):
            raw = getattr(self, "_status_for_test", JobStatus.FAILED.value)
            return JobStatus(raw) if not isinstance(raw, JobStatus) else raw
        raw=self._status_only()
        return JobStatus(raw) if raw else JobStatus.FAILED
    @status.setter
    def status(self, value: JobStatus):
        if not hasattr(self, "job_id"):
            self._status_for_test = value.value if isinstance(value, JobStatus) else str(value)
            return
        new_status = value.value if isinstance(value, JobStatus) else str(value)
        def _set_status(row):
            row.status = new_status
            if new_status in _TERMINAL_JOB_STATUSES:
                self._flush_live_to_row(row)
        self._write(_set_status)
    @property
    def progress(self):
        row=self._row(defer_result=True, defer_payload=True); return row.progress if row else 0
    @progress.setter
    def progress(self, value):
        self._write(lambda row: setattr(row, "progress", max(0, min(100, int(value)))), background=True)
    @property
    def current_engine(self):
        row=self._row(defer_result=True, defer_payload=True); return row.current_engine if row else None
    @current_engine.setter
    def current_engine(self, value):
        self._write(lambda row: setattr(row, "current_engine", value), background=True)
        if value: self.record_event('engine', stage=str(value), tool=str(value), message=f'Engine selected: {value}')
    @property
    def result(self):
        row=self._row(); return row.result if row else None
    @result.setter
    def result(self, value):
        self._write(lambda row: setattr(row, "result", jsonable(value)), cache=False)
    @property
    def error_message(self):
        row=self._row(defer_result=True, defer_payload=True); return row.error_message if row else None
    @error_message.setter
    def error_message(self, value):
        # NOTE: must check "is not None", not truthiness. Some exceptions
        # (e.g. asyncio.TimeoutError()) stringify to "", which is falsy -
        # `if value` was silently turning a real failure reason into None,
        # and callers then logged the literal text "None" instead of the
        # actual error.
        self._write(lambda row: setattr(row, "error_message", str(value)[:2000] if value is not None else None))
    def log(self, message: str):
        line=f"{utcnow().isoformat()} {str(message)[:1000]}"
        def _mutate(row):
            row.logs=(row.logs or [])+ [line]
            row.logs=row.logs[-settings.MAX_JOB_LOGS:]
        self._write(_mutate, background=True)
        self.record_event('log', message=str(message)[:4000])
    async def heartbeat(self):
        def _mutate(row):
            # Timestamp taken when the write actually runs, so a coalesced or
            # delayed heartbeat never records an older time than reality.
            now = utcnow()
            row.heartbeat_at = now
            from datetime import timedelta
            row.lease_until = now + timedelta(seconds=120)
        self._write(_mutate, activity=False, background=True, key=("heartbeat", self.job_id))

    async def checkpoint(self, engine: str | None = None):
        if engine: self.current_engine=engine
        await self.heartbeat()
        while True:
            status=self.status
            if status == JobStatus.CANCELLED: raise asyncio.CancelledError
            if status != JobStatus.PAUSED: return
            self.log("Waiting while paused")
            await asyncio.sleep(0.5)

    def _progress_meta(self):
        row=self._row(defer_result=True)
        if not row: return {}
        payload=row.payload or {}
        return payload.get("_live_progress") or {}

    def initialize_stages(self, stages: list[tuple[str,str]]):
        """Create the complete stage tree in one durable transaction.

        Always starts every stage at "pending", regardless of whatever a
        prior run may have left in this job row's payload. Previously this
        reused any pre-existing stage entry verbatim (including its old
        "completed"/"failed" status), so a job_id/row that had ever been
        touched by an earlier attempt (a resume after pause, a retry after
        failure, a worker restart mid-scan) would show stages such as
        "Finalize results" as already COMPLETED the instant a brand-new run
        started — before that stage had actually executed even once in the
        current run. A fresh run must always start from a clean, honest
        stage tree.
        """
        def _mutate(row):
            payload=dict(row.payload or {})
            meta=dict(payload.get("_live_progress") or {})
            now=utcnow().isoformat()
            ordered=[
                {"id":sid,"label":label,"status":"pending","progress":0,"started_at":None,"finished_at":None,"message":""}
                for sid,label in stages
            ]
            meta["stages"]=ordered
            meta["total_tasks"]=len(ordered)
            _apply_task_counts(meta, ordered)
            meta["updated_at"]=now
            payload["_live_progress"]=meta
            row.payload=payload
        self._write(_mutate)

    def set_stage(self, stage_id: str, status: str, *, label: str | None = None, message: str = "", progress: int | None = None, eta_hint_seconds: float | None = None, tool: str | None = None):
        """Persist structured live progress without changing the DB schema.

        The live state lives under payload._live_progress so older deployments and
        existing scan_jobs tables remain compatible. Credentials are never copied.

        Wrapped in self._write() (with_db_retry underneath) since 2026-09-15: a
        DB write here failing on a single transient SSL EOF used to silently
        drop that one stage transition and, combined with the Redis
        fire-and-forget write race fixed the same day in _cache_snapshot(),
        was the pair of bugs behind a scan's progress view briefly showing an
        earlier stage than it had actually reached.
        """
        call_time=utcnow().isoformat()  # stage timestamps reflect when it happened, not when the queued write ran
        def _mutate(row):
            payload=dict(row.payload or {})
            meta=dict(payload.get("_live_progress") or {})
            stages=list(meta.get("stages") or [])
            now=call_time
            found=next((x for x in stages if x.get("id") == stage_id), None)
            if found is None:
                found={"id":stage_id,"label":label or stage_id,"status":status,"progress":int(progress or 0),"started_at":None,"finished_at":None,"message":""}
                stages.append(found)
            found["label"]=label or found.get("label") or stage_id
            found["status"]=status
            if progress is not None: found["progress"]=max(0,min(100,int(progress)))
            if message: found["message"]=str(message)[:500]
            if eta_hint_seconds is not None: found["eta_hint_seconds"] = max(0.0, float(eta_hint_seconds))
            if tool: found["tool"] = str(tool)[:128]
            if status == "running" and not found.get("started_at"): found["started_at"]=now
            if status in {"completed","failed","skipped","partial"} : found["finished_at"]=now
            meta["stages"]=stages
            meta["total_tasks"]=len(stages)
            _apply_task_counts(meta, stages)
            meta["updated_at"]=now
            payload["_live_progress"]=meta
            row.payload=payload
        self._write(_mutate, background=True)
        try:
            from app.core import execution_trace as _trace
            if status == "running":
                _trace.set_scope(stage_id, tool or stage_id)
            elif status in {"completed", "failed", "skipped", "partial"}:
                _trace.clear_scope_if(stage_id)
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        self.record_event('stage', stage=stage_id, message=message or status, payload={'status': status, 'progress': progress, 'label': label or stage_id})

    def _cache_snapshot(self, row=None):
        """Publish a lightweight snapshot without the potentially huge result."""
        global _hot_cache_disabled_until
        if time.monotonic() < _hot_cache_disabled_until:
            return
        r = _hot_cache()
        if r is None:
            return
        if row is None:
            row = self._row(defer_result=True)
        if not row:
            return
        meta=(row.payload or {}).get("_live_progress") or {}
        stages=meta.get("stages") or []
        data={
            "job_id":row.job_id,"job_type":row.job_type,"target":row.target,
            "status":row.status,"progress":row.progress,"current_engine":row.current_engine,
            "logs":(row.logs or [])[-100:],"created_at":row.created_at.isoformat(),
            "started_at":row.started_at.isoformat() if row.started_at else None,
            "finished_at":row.finished_at.isoformat() if row.finished_at else None,
            "error_message":row.error_message,"execution_config":_safe_execution_config(row.payload),"stages":stages,
            "completed_tasks":int(meta.get("completed_tasks",0)),
            "total_tasks":int(meta.get("total_tasks",len(stages))),
            "task_breakdown":dict(meta.get("task_breakdown") or {}),
            "execution_id":(row.payload or {}).get("_execution_id"),
        }
        try:
            # 2026-09-15 fix: this used to be `asyncio.create_task(asyncio.to_thread(...))`
            # — fire-and-forget. Each call to set_stage() (stage 3, then stage 4, then
            # stage 5...) spawned its own detached write to the SAME Redis key with no
            # ordering guarantee between them. Under the network jitter this deployment
            # already sees against Supabase (see with_db_retry's docstring), a slower
            # earlier write (e.g. stage 3) could land in Redis AFTER a faster later one
            # (e.g. stage 6), so a page refresh right after that would read() the stale
            # stage-3 snapshot back — exactly the "scan reverted to an earlier stage,
            # then caught back up" symptom. set_stage() calls are already sequential in
            # the caller (manager.py awaits each stage before moving to the next), so a
            # plain blocking call here preserves that same order: this write finishes
            # (or times out at socket_timeout=1s, see _hot_cache()) before set_stage()
            # returns and the caller can start the *next* stage's write.
            r.setex(_hot_key(row.tenant_id,row.job_id), _HOT_CACHE_TTL_SECONDS, json.dumps(data, separators=(",",":")))
        except Exception:
            # Do not let a dead Redis server turn every progress mutation into
            # a one-second timeout. The durable DB path remains fully usable.
            _hot_cache_disabled_until = time.monotonic() + 30

    async def snapshot_async(self) -> JobSnapshot:
        return await asyncio.to_thread(self.snapshot)

    def snapshot(self) -> JobSnapshot:
        # Hot path: read only the compact progress state from Redis. This avoids
        # repeated Supabase/Postgres round-trips while a worker is updating a job.
        tid = tenant_context.get() or "legacy"
        r = None if time.monotonic() < _hot_cache_disabled_until else _hot_cache()
        if r is not None:
            try:
                raw=r.get(_hot_key(tid,self.job_id))
                if raw:
                    data=json.loads(raw)
                    started=datetime_from_iso(data.get("started_at"))
                    finished=datetime_from_iso(data.get("finished_at"))
                    now=utcnow()
                    duration=None
                    if started:
                        end=finished or now; duration=max(0,(end-started).total_seconds())
                    status=data.get("status")
                    progress=int(data.get("progress") or 0)
                    eta=None; current_eta=None
                    if status in {"pending","running","paused"}:
                        eta,current_eta=_stage_eta(data.get("stages") or [], now)
                    result=None
                    if status in {"completed","partial","failed","cancelled"}:
                        # Terminal snapshots need the durable result once; live
                        # progress frames deliberately never carry the heavy result.
                        try:
                            result=self._result_only()
                        except Exception:
                            result=None
                    return JobSnapshot(**data, result=result, duration_seconds=duration,
                        elapsed_seconds=round(duration or 0.0,1), eta_seconds=round(eta,1) if eta is not None else None, current_eta_seconds=round(current_eta,1) if current_eta is not None else None,
                        eta_finish_at=(now + timedelta(seconds=eta)).isoformat() if eta is not None else None,
                        current_eta_finish_at=(now + timedelta(seconds=current_eta)).isoformat() if current_eta is not None else None)
            except Exception:
                logger.debug("Redis hot-cache snapshot read failed for job %s; falling back to DB row", self.job_id, exc_info=True)
        row=self._row(defer_result=True)
        if not row: raise KeyError(self.job_id)
        final_result=self._result_only() if row.status in _TERMINAL_JOB_STATUSES else None
        duration=None
        if row.started_at:
            end=row.finished_at or utcnow(); duration=max(0,(end-row.started_at).total_seconds())
        meta=(row.payload or {}).get("_live_progress") or {}
        stages=meta.get("stages") or []
        elapsed=duration or 0.0
        eta=None; current_eta=None
        if row.status in {JobStatus.PENDING.value,JobStatus.RUNNING.value,JobStatus.PAUSED.value}:
            eta,current_eta=_stage_eta(stages, utcnow())
        self._cache_snapshot(row)
        return JobSnapshot(job_id=row.job_id,job_type=row.job_type,target=row.target,status=JobStatus(row.status),
            progress=row.progress,current_engine=row.current_engine,logs=(row.logs or [])[-100:],
            created_at=row.created_at,started_at=row.started_at,finished_at=row.finished_at,
            duration_seconds=duration,error_message=row.error_message,result=final_result,
            execution_config=_safe_execution_config(row.payload),
            stages=stages,elapsed_seconds=round(elapsed,1),eta_seconds=round(eta,1) if eta is not None else None,
            current_eta_seconds=round(current_eta,1) if current_eta is not None else None,
            eta_finish_at=(utcnow() + timedelta(seconds=eta)).isoformat() if eta is not None else None,
            current_eta_finish_at=(utcnow() + timedelta(seconds=current_eta)).isoformat() if current_eta is not None else None,
            completed_tasks=int(meta.get("completed_tasks",0)),total_tasks=int(meta.get("total_tasks",len(stages))), task_breakdown=dict(meta.get("task_breakdown") or {}), execution_id=(row.payload or {}).get("_execution_id"))


    def close_open_stages(self, final_status: str | None = None):
        """Close any pending/running stages when a job reaches a terminal state."""
        status = final_status or str(self.status.value if hasattr(self.status, "value") else self.status)
        target = "failed" if status == "failed" else "skipped"
        message = "Job failed before this stage completed" if target == "failed" else "Job finished before this stage ran"
        for stage in (self._progress_meta().get("stages") or []):
            if stage.get("status") in {"pending", "running"}:
                self.set_stage(stage.get("id", "unknown"), target, progress=int(stage.get("progress") or 0), message=message)


class JobManager:
    def __init__(self):
        if settings.DB_AUTO_CREATE_SCHEMA: init_db_with_retry()
        self._tasks: dict[str,asyncio.Task]={}

    async def create(self, job_type: str, target: str, runner: Callable[[JobRecord], Awaitable[Any]] | None = None,
                     start: bool = True, payload: dict | None = None) -> JobRecord:
        tenant_id=tenant_context.get() or "legacy"
        # Every requested scan gets a durable job/history record. Policy admission
        # is enforced by the HTTP routes before this method is called.
        job=JobRecord(str(uuid.uuid4()),job_type,target)
        initial_payload=protect_job_payload(payload)
        initial_payload["_live_progress"]={"stages":[],"completed_tasks":0,"total_tasks":0}
        created_at = utcnow()
        # Two DB writes that, unlike the routine progress updates above, are not
        # self-healing on the next poll: if the very first commit here fails on a
        # transient SSL EOF, the scan never gets a durable row at all and the
        # POST /platform/scan/async request itself would 500 instead of the
        # normal 202 Accepted.
        def _create_rows():
            with session_scope_sync() as db:
                tenant = tenant_context.get() or "legacy"
                principal = current_principal_optional()
                owner_user_id = principal.user_id if principal else None
                db.add(JobRow(job_id=job.job_id,tenant_id=tenant,created_by_user_id=owner_user_id,job_type=job_type,target=target,status=JobStatus.PENDING.value,
                              progress=0,logs=[],payload=initial_payload,created_at=created_at,heartbeat_at=None,lease_owner=None,lease_until=None,attempt_count=0))
                db.add(ScanRow(scan_id=job.job_id, tenant_id=tenant, created_by_user_id=owner_user_id, job_id=job.job_id, scan_kind=job_type,
                               target=target, status=JobStatus.PENDING.value, result=None, error_message=None,
                               created_at=created_at, finished_at=None))
        with_db_retry(_create_rows)
        # Seed the hot cache immediately so the first progress request is instant.
        try:
            with session_scope_sync() as db:
                row=_owned_row(db,job.job_id)
                if row: job._cache_snapshot(row)
        except Exception:
            logger.debug("Failed to seed hot cache for new job %s", job.job_id, exc_info=True)
        if start and runner: self.start(job,runner)
        return job

    def _redis(self):
        if not settings.JOB_QUEUE_ENABLED or not settings.REDIS_URL or redis is None: return None
        return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

    def start(self, job: JobRecord, runner: Callable[[JobRecord], Awaitable[Any]], payload: dict | None = None):
        r=self._redis()
        if r is not None and not settings.WORKER_MODE:
            try:
                with session_scope_sync() as db:
                    row=_owned_row(db,job.job_id)
                    if row and payload is not None:
                        # Never re-introduce plaintext credentials when the API
                        # starts/queues a job after create().
                        safe_payload = protect_job_payload(payload)
                        # Preserve the durable live-progress checkpoint created by
                        # JobManager.create(). The queue payload must not erase it.
                        current = dict(row.payload or {})
                        current.update(safe_payload)
                        if "_live_progress" in row.payload:
                            current["_live_progress"] = row.payload["_live_progress"]
                        row.payload = current
                from app.core.redis_queue import enqueue
                # Redis transport is offloaded from the API event loop. Postgres
                # remains canonical; the worker re-enqueues pending rows if this
                # process dies after commit and before XADD.
                asyncio.create_task(asyncio.to_thread(enqueue, r, job.job_id, job.job_type))
                job.log("Job queued on durable Redis Stream")
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
        started_at = utcnow()
        def _mark_started():
            with session_scope_sync() as db:
                row=_owned_row(db,job.job_id)
                if row: row.started_at=started_at
                scan_row=db.get(ScanRow, job.job_id)
                if scan_row and scan_row.tenant_id == (tenant_context.get() or "legacy"):
                    scan_row.status=JobStatus.RUNNING.value
                    scan_row.created_at=scan_row.created_at or started_at
        with_db_retry(_mark_started)
        job.start_execution(started_at)
        execution_id = job.execution_id
        job.log("Job started")
        try:
            tenant_id = tenant_context.get() or "legacy"
            # Durable scans are intentionally independent of tenant quotas
            # and concurrency gates. They DO still respect
            # max_scan_duration_minutes below (0/default = no time limit).
            await job.checkpoint("queued")
            duration = scan_timeout_seconds(tenant_id)
            result=await asyncio.wait_for(runner(job), timeout=duration)
            if job.status != JobStatus.CANCELLED:
                if getattr(result, "module", None) in {"web", "network", "api_security"}:
                    try:
                        from app.core.finding_pipeline import correlate_and_escalate
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
                        job.log(f"SOC pipeline warning: {str(exc)[:1000]}")
                job.result=result; job.progress=100; job.current_engine=None
                with session_scope_sync() as db:
                    scan_row=db.get(ScanRow, job.job_id)
                    if scan_row and scan_row.tenant_id == (tenant_context.get() or "legacy"):
                        scan_row.result=jsonable(result)
                        scan_row.status=JobStatus.PARTIAL.value if getattr(result, "status", "completed") == "partial" else JobStatus.COMPLETED.value
                job.set_stage("finalize", "completed", progress=100, message="Scan snapshot finalized")
                if getattr(result, "status", "completed") == "partial":
                    job.status=JobStatus.PARTIAL; job.log("Job completed with partial module coverage")
                else:
                    job.status=JobStatus.COMPLETED; job.log("Job completed")
        except asyncio.CancelledError:
            job.status=JobStatus.CANCELLED; job.error_message="Job cancelled"; job.log("Job cancelled")
        except Exception as exc:
            if job.current_engine: job.set_stage(job.current_engine, "failed", progress=100, message=str(exc)[:500])
            job.status=JobStatus.FAILED; job.error_message=str(exc)[:2000]; job.log(f"Job failed: {job.error_message}")
        finally:
            finished_at = utcnow()
            try:
                job.close_open_stages(job.status.value if hasattr(job.status, "value") else str(job.status))
            except Exception:
                logger.debug("failed to close open stages for %s", job.job_id, exc_info=True)
            # 2026-09-15: this is the ONLY place ScanRow (the row scan-history
            # reads) gets synced to the job's final status. It runs inside a
            # `finally`, so an unretried SSL EOF here used to raise past the
            # finally block entirely (an exception raised in `finally` wins
            # over anything before it) as an unhandled asyncio Task exception
            # — the scan had actually finished correctly, but its
            # scan_history row could be left showing "running" forever since
            # nothing else would ever come back to fix it.
            def _finalize():
                with session_scope_sync() as db:
                    row=_owned_row(db,job.job_id)
                    if row: row.finished_at=finished_at
                    scan_row=db.get(ScanRow, job.job_id)
                    if scan_row and scan_row.tenant_id == (tenant_context.get() or "legacy"):
                        scan_row.status = job.status.value
                        scan_row.error_message = job.error_message
                        if job.result is not None:
                            scan_row.result = jsonable(job.result)
                        scan_row.finished_at = finished_at
                    row=_owned_row(db,job.job_id)
                    if row:
                        row.finished_at=finished_at
                        job._cache_snapshot(row)
                    exec_row = db.get(ScanExecutionRow, execution_id) if execution_id else None
                    if exec_row:
                        exec_row.status = job.status.value
                        exec_row.current_engine = job.current_engine
                        exec_row.finished_at = finished_at
            with_db_retry(_finalize)
            try:
                await asyncio.get_running_loop().run_in_executor(None, _trace.flush)
                _trace.forget(execution_id)
            except Exception:
                logger.debug('trace flush failed', exc_info=True)
            job.record_event('execution_finished', message=f'Execution {job.status.value}', payload={'status': job.status.value})

    def get(self, job_id):
        def _read():
            with session_scope_sync() as db:
                # Only 4 small columns: this runs on every /jobs/{id} call and every control action.
                rec=db.execute(select(JobRow.job_id,JobRow.job_type,JobRow.target,JobRow.tenant_id).where(JobRow.job_id==job_id)).first()
                if not rec: return None
                tid=tenant_context.get()
                visible=(rec[3]=="legacy") if tid is None else (rec[3]==tid)  # same fail-closed rule as _owned_row
                return JobRecord(rec[0],rec[1],rec[2],self._tasks.get(job_id)) if visible else None
        return with_db_retry(_read)

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
        if not job: return False
        # Cancelling an already cancel_requested job is NOT a conflict — the
        # caller's intent ("stop this job") is already satisfied/in-flight.
        # Returning False here (old behavior) made the API answer "cannot be
        # cancelled" for a job that in fact CAN be and IS being cancelled,
        # which is misleading and caused the frontend to show a false error
        # on every retry after the first successful cancel request.
        if job.status == JobStatus.CANCEL_REQUESTED:
            return True
        if job.status in {JobStatus.COMPLETED,JobStatus.FAILED,JobStatus.CANCELLED}: return False
        job.status=JobStatus.CANCEL_REQUESTED; job.log("Cancel requested")
        task=self._tasks.get(job_id)
        if task and not task.done(): task.cancel()
        return True

    async def update(self, job, *, progress=None, engine=None, message=None):
        if progress is not None: job.progress=progress
        if engine is not None: job.current_engine=engine
        if message: job.log(message)

job_manager=JobManager()
