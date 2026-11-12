"""Stall watchdog for scan jobs running inside the worker.

Why this exists
---------------
On 2026-10-04 a full scan froze at ~55%: the worker wrote nothing for ~31
minutes (last heartbeat 21:38:29, last progress 21:38:56) while the UI kept
showing "running". Nothing in the system recorded *that* it had stalled or why.

What it does
------------
* Tracks the last time a job made real progress: a progress/log/stage write
  to its row (heartbeats do NOT count - they would hide a stall) or a chunk
  of tool output persisted by CanonicalStreamRecorder.
* A dedicated daemon THREAD (not an asyncio task - an asyncio watchdog would
  freeze together with a blocked event loop) checks every few seconds.
* If a running job has made no progress for WORKER_STALL_SECONDS (default
  180s) it logs the reason to stderr first (always works, even when the DB is
  down), then best-effort records it on the job: a line in the live log and a
  ``_live_progress.stalled`` marker (since / idle_seconds / cause / reason).
* When progress resumes it clears the marker and logs how long the stall was.

By default it never cancels, fails or otherwise changes the job's status (opt-in
``dead_seconds``/``on_dead`` escalation exists for zombie jobs): a quiet tool
(e.g. a long ffuf/nuclei run with no output) is legitimate, so the watchdog
only reports, with enough diagnostics to tell the causes apart:
  event_loop_blocked | database_unreachable | redis_unreachable | tools_silent
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger("mirsad.stall_watchdog")

_activity: dict[str, float] = {}
_activity_lock = threading.Lock()


def touch(job_id: str | None) -> None:
    """Record real progress for ``job_id`` (cheap, thread-safe, never raises)."""
    if not job_id:
        return
    try:
        with _activity_lock:
            _activity[str(job_id)] = time.monotonic()
    except Exception:  # pragma: no cover - must never break a scan
        logger.debug("suppressed non-fatal error", exc_info=True)


def last_activity(job_id: str) -> float | None:
    with _activity_lock:
        return _activity.get(str(job_id))


def forget(job_id: str) -> None:
    with _activity_lock:
        _activity.pop(str(job_id), None)


def _run_with_timeout(fn: Callable[[], Any], timeout: float) -> tuple[bool, Any]:
    """Run ``fn`` in a throwaway daemon thread; (False, reason) on timeout/error."""
    box: dict[str, Any] = {}

    def _target():
        try:
            box["value"] = fn()
        except Exception as exc:  # noqa: BLE001
            box["error"] = f"{type(exc).__name__}: {exc}"[:200]

    context = contextvars.copy_context()
    t = threading.Thread(target=lambda: context.run(_target), daemon=True, name="stall-probe")
    t.start()
    t.join(timeout)
    if t.is_alive():
        return False, f"timed out after {timeout:.0f}s"
    if "error" in box:
        return False, box["error"]
    return True, box.get("value")


class StallWatchdog:
    """One instance per running job. ``start()`` must be called from the job's event loop."""

    def __init__(self, job, *, threshold_seconds: float = 180.0, check_seconds: float = 15.0,
                 redis_url: str | None = None, dead_seconds: float = 0.0,
                 on_dead: Callable[[float], None] | None = None):
        self.job = job
        # The watchdog runs outside the worker's asyncio task. Preserve the tenant
        # context so its DB reads/writes remain scoped to the same job.
        self._context = contextvars.copy_context()
        # Opt-in escalation (2026-10-13): a job that wrote NOTHING for ``dead_seconds`` is a
        # zombie holding a concurrency slot; ``on_dead`` (called once, from the watchdog thread)
        # lets the worker cancel it. 0 = report only (the original behaviour).
        self.dead_seconds = max(0.0, float(dead_seconds or 0.0))
        self.on_dead = on_dead
        self._dead_fired = False
        self.job_id = str(job.job_id)
        self.threshold = max(30.0, float(threshold_seconds))
        self.check = max(1.0, float(check_seconds))
        self.redis_url = redis_url
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ticker: asyncio.Task | None = None
        self._loop_tick = time.monotonic()
        self._stalled_since: float | None = None

    # ---- lifecycle -------------------------------------------------------
    def start(self) -> None:
        touch(self.job_id)
        self._loop_tick = time.monotonic()

        async def _tick():
            while True:
                self._loop_tick = time.monotonic()
                await asyncio.sleep(1.0)

        try:
            self._ticker = asyncio.get_running_loop().create_task(_tick())
        except RuntimeError:  # no running loop (tests): lag is then not measured
            self._ticker = None
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"stall-watchdog-{self.job_id[:8]}")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._ticker:
            self._ticker.cancel()
        forget(self.job_id)

    # ---- main loop (runs in its own thread) ------------------------------
    def _run(self) -> None:
        while not self._stop.wait(self.check):
            try:
                self._context.copy().run(self._check_once)
            except Exception:  # noqa: BLE001
                logger.debug("stall watchdog pass failed", exc_info=True)

    def _check_once(self) -> None:
        now = time.monotonic()
        seen = last_activity(self.job_id)
        idle = (now - seen) if seen is not None else 0.0

        if self._stalled_since is None:
            if idle < self.threshold:
                return
            ok, status = _run_with_timeout(lambda: self.job.status, 8)
            if ok and str(getattr(status, "value", status)).lower() == "paused":
                return  # a paused job is expected to be silent
            cause, reason = self._diagnose(idle)
            self._stalled_since = now - idle
            logger.error("JOB STALLED %s: %s", self.job_id, reason)
            self._record(stalled={
                "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - idle)),
                "idle_seconds": int(idle), "cause": cause, "reason": reason,
            }, line=f"STALLED: {reason}")
        elif idle < self.threshold:
            lasted = int(now - self._stalled_since)
            self._stalled_since = None
            logger.warning("Job %s resumed after a stall of ~%ds", self.job_id, lasted)
            self._record(stalled=None, line=f"Resumed after a stall of ~{lasted}s")
        elif (self.on_dead is not None and self.dead_seconds > 0 and idle >= self.dead_seconds
              and not self._dead_fired):
            self._dead_fired = True
            logger.error("JOB DEAD %s: no progress for %ds (>= %ds); requesting cancellation",
                         self.job_id, int(idle), int(self.dead_seconds))
            self._record(stalled={"since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - idle)),
                                  "idle_seconds": int(idle), "cause": "dead_job_cancelled",
                                  "reason": f"no progress for {int(idle)}s; cancelling zombie job"},
                         line=f"DEAD: no progress for {int(idle)}s; cancelling")
            try:
                self.on_dead(idle)
            except Exception:  # noqa: BLE001
                logger.exception("on_dead callback failed for job %s", self.job_id)
        # otherwise still stalled: nothing more to say, the marker is already recorded

    # ---- diagnostics -----------------------------------------------------
    def _diagnose(self, idle: float) -> tuple[str, str]:
        lag = max(0.0, time.monotonic() - self._loop_tick) if self._ticker else 0.0

        def _db():
            from sqlalchemy import text
            from app.core.database import session_scope_sync
            with session_scope_sync() as db:
                db.execute(text("select 1"))
            return True

        db_ok, db_info = _run_with_timeout(_db, 10)

        redis_ok, redis_info = True, "n/a"
        if self.redis_url:
            def _redis():
                import redis
                return redis.Redis.from_url(self.redis_url, socket_connect_timeout=3, socket_timeout=3).ping()
            redis_ok, redis_info = _run_with_timeout(_redis, 6)

        running = self._running_stages()
        if lag > 30:
            cause = "event_loop_blocked"
        elif not db_ok:
            cause = "database_unreachable"
        elif not redis_ok:
            cause = "redis_unreachable"
        else:
            cause = "tools_silent"
        reason = (f"no progress write for {int(idle)}s (threshold {int(self.threshold)}s); cause={cause}; "
                  f"event_loop_lag={lag:.0f}s; db={'ok' if db_ok else db_info}; "
                  f"redis={'ok' if redis_ok else redis_info}; running={running or 'none'}")
        return cause, reason

    def _running_stages(self) -> str:
        def _read():
            row = self.job._row()
            meta = ((row.payload or {}).get("_live_progress") or {}) if row else {}
            return ",".join(str(s.get("id")) for s in (meta.get("stages") or []) if s.get("status") == "running")
        ok, val = _run_with_timeout(_read, 8)
        return val if ok else ""

    # ---- persistence (best effort, never counts as progress) ------------
    def _record(self, *, stalled: dict | None, line: str) -> None:
        from app.core.database import utcnow
        from app.core.config import settings
        max_logs = getattr(settings, "MAX_JOB_LOGS", 500)
        stamped = f"{utcnow().isoformat()} {line[:1000]}"

        def _mutate(row):
            payload = dict(row.payload or {})
            meta = dict(payload.get("_live_progress") or {})
            if stalled is None:
                meta.pop("stalled", None)
            else:
                meta["stalled"] = stalled
            payload["_live_progress"] = meta
            row.payload = payload
            row.logs = ((row.logs or []) + [stamped])[-max_logs:]

        ok, info = _run_with_timeout(lambda: self.job._write(_mutate, activity=False), 20)
        if not ok:
            logger.error("Could not record stall state for job %s: %s", self.job_id, info)
