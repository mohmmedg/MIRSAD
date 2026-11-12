"""SQLMap retries a dropped connection with linear backoff, up to SQLMAP_CONNECT_RETRY_ATTEMPTS
times, only while the target keeps answering on preflight and the time budget allows it
(2026-11-01 incident: a single fixed-30s retry did not recover; 2026-11-02 fix: retry harder)."""
import asyncio

from app.modules.external_scanners import engines


def _run(monkeypatch, statuses, preflight_ok=True, retry_attempts=3):
    calls = []

    async def fake_run_sqlmap(url, **kw):
        calls.append(url)
        st = statuses[min(len(calls) - 1, len(statuses) - 1)]
        return {"status": st, "findings": [], "reason": "sqlmap lost the connection to the target URL" if st == "FAILED" else None}

    async def fake_preflight(url):
        return preflight_ok, None

    async def no_sleep(_):
        return None

    monkeypatch.setattr(engines, "run_sqlmap", fake_run_sqlmap)
    monkeypatch.setattr(engines, "_preflight", fake_preflight)
    monkeypatch.setattr(engines.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *a, **k: [{"url": "http://t/x?q=1", "data": None, "extra_args": [], "label": "GET parameters"}])
    # This file tests retry logic only; the precheck (test_sqlmap_precheck.py) makes a real
    # HTTP request and is covered separately, so keep it off here for determinism/offline tests.
    monkeypatch.setattr(engines.settings, "SQLMAP_PRECHECK_GET_TARGETS", False)
    monkeypatch.setattr(engines.settings, "SQLMAP_CONNECT_RETRY_ATTEMPTS", retry_attempts)
    monkeypatch.setattr(engines.settings, "SQLMAP_CONNECT_RETRY_BASE_SECONDS", 20)
    res = asyncio.run(engines.run_sqlmap_multi("http://t", safe_mode="safe", timeout_seconds=1000))
    return res, calls


def test_retry_recovers(monkeypatch):
    res, calls = _run(monkeypatch, ["FAILED", "COMPLETED"])
    assert len(calls) == 2 and res["status"] == "COMPLETED"


def test_no_retry_when_target_still_down(monkeypatch):
    res, calls = _run(monkeypatch, ["FAILED", "COMPLETED"], preflight_ok=False)
    assert len(calls) == 1 and res["status"] == "FAILED"


def test_retries_until_attempts_exhausted(monkeypatch):
    """Every attempt keeps failing with a 'connection' reason: the loop must retry
    SQLMAP_CONNECT_RETRY_ATTEMPTS times (not just once) before giving up."""
    res, calls = _run(monkeypatch, ["FAILED"], retry_attempts=3)
    assert len(calls) == 1 + 3 and res["status"] == "FAILED"


def test_retry_attempts_configurable(monkeypatch):
    """SQLMAP_CONNECT_RETRY_ATTEMPTS=0 must restore the old no-retry behaviour exactly."""
    res, calls = _run(monkeypatch, ["FAILED"], retry_attempts=0)
    assert len(calls) == 1 and res["status"] == "FAILED"
