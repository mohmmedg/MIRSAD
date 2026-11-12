"""Stall watchdog: flags after N silent seconds, ignores heartbeats, clears on resume."""
import time
import types

from app.core import stall_watchdog as sw


class _Job:
    job_id = "job-test-1"


class _Probe(sw.StallWatchdog):
    """Replace DB/Redis diagnostics and persistence so no services are needed."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = []
    def _diagnose(self, idle):
        return "tools_silent", f"idle {int(idle)}s"
    def _record(self, *, stalled, line):
        self.records.append((stalled, line))


def _make(threshold=30.0):
    job = _Job()
    w = _Probe(job, threshold_seconds=threshold, check_seconds=1)
    # status probe must not touch a DB
    job.status = types.SimpleNamespace(value="running")
    return w


def test_no_flag_while_progress_is_recent():
    w = _make()
    sw.touch(w.job_id)
    w._check_once()
    assert w.records == []


def test_flags_once_after_threshold_then_clears_on_progress():
    w = _make(threshold=30.0)
    sw._activity[w.job_id] = time.monotonic() - 45   # silent for 45s
    w._check_once()
    assert len(w.records) == 1 and w.records[0][0]["cause"] == "tools_silent"
    w._check_once()                                   # still stalled: no duplicate record
    assert len(w.records) == 1
    sw.touch(w.job_id)                                # progress resumes
    w._check_once()
    assert len(w.records) == 2 and w.records[1][0] is None


def test_paused_job_is_not_flagged():
    w = _make()
    w.job.status = types.SimpleNamespace(value="paused")
    sw._activity[w.job_id] = time.monotonic() - 999
    w._check_once()
    assert w.records == []


def test_dead_job_escalation_fires_once_when_enabled():
    fired = []
    w = _make(threshold=30.0)
    w.dead_seconds = 120.0
    w.on_dead = lambda idle: fired.append(idle)
    sw._activity[w.job_id] = time.monotonic() - 45
    w._check_once()                       # flagged as stalled, not dead yet
    assert fired == []
    sw._activity[w.job_id] = time.monotonic() - 200
    w._check_once()
    w._check_once()
    assert len(fired) == 1                # fires exactly once


def test_dead_escalation_is_off_by_default():
    w = _make(threshold=30.0)
    sw._activity[w.job_id] = time.monotonic() - 99999
    w._check_once(); w._check_once()
    assert all(r[0] is None or r[0]["cause"] != "dead_job_cancelled" for r in w.records)


def test_run_with_timeout_propagates_contextvars_to_probe_thread():
    import contextvars

    tenant = contextvars.ContextVar("tenant_for_watchdog_test", default=None)
    token = tenant.set("tenant-123")
    try:
        ok, value = sw._run_with_timeout(tenant.get, 1.0)
    finally:
        tenant.reset(token)

    assert ok is True
    assert value == "tenant-123"


def test_watchdog_thread_runs_checks_in_captured_context():
    import contextvars

    marker = contextvars.ContextVar("watchdog_thread_context_test", default=None)
    token = marker.set("tenant-context")
    try:
        w = _make()
        w.check = 0.01
        seen = []

        def check_once():
            seen.append(marker.get())
            w._stop.set()

        w._check_once = check_once
        w._run()
    finally:
        marker.reset(token)

    assert seen == ["tenant-context"]
