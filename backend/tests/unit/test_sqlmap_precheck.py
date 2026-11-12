"""select_sqlmap_targets() can reconstruct a GET URL/query shape that does not actually exist
(portal.cpu.edu.sy, 2026-11-01: 2 of 4 sqlmap targets were 404s, each burning a full per-target
time slice for nothing). run_sqlmap_multi now precheck-probes GET candidates and skips a 404
without spending sqlmap/ghauri time on it. POST candidates are never precheck-probed (submitting
data has side effects)."""
import asyncio

import httpx
import pytest

from app.modules.external_scanners import engines


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeAsyncClient:
    """Stands in for httpx.AsyncClient so the test makes no real network call."""

    def __init__(self, status_by_url, calls):
        self._status_by_url = status_by_url
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        self._calls.append(url)
        return _FakeResponse(self._status_by_url.get(url, 200))


def _patch_common(monkeypatch, sqlmap_statuses, status_by_url):
    sqlmap_calls = []
    precheck_calls = []

    async def fake_run_sqlmap(url, **kw):
        sqlmap_calls.append(url)
        st = sqlmap_statuses[min(len(sqlmap_calls) - 1, len(sqlmap_statuses) - 1)]
        return {"status": st, "findings": [], "reason": None}

    def fake_async_client(*a, **k):
        return _FakeAsyncClient(status_by_url, precheck_calls)

    monkeypatch.setattr(engines, "run_sqlmap", fake_run_sqlmap)
    monkeypatch.setattr(engines.httpx, "AsyncClient", fake_async_client)
    monkeypatch.setattr(engines.settings, "SQLMAP_PRECHECK_GET_TARGETS", True)
    return sqlmap_calls, precheck_calls


def test_404_get_target_is_skipped_without_calling_sqlmap(monkeypatch):
    targets = [{"url": "http://t/guessed?x=1", "data": None, "extra_args": [], "label": "GET form"}]
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *a, **k: targets)
    sqlmap_calls, precheck_calls = _patch_common(monkeypatch, ["COMPLETED"], {"http://t/guessed?x=1": 404})

    res = asyncio.run(engines.run_sqlmap_multi("http://t", safe_mode="safe", timeout_seconds=1000))

    assert precheck_calls == ["http://t/guessed?x=1"]
    assert sqlmap_calls == []  # sqlmap must never be invoked for a confirmed-404 target
    assert res["status"] == "NOT_TESTED"
    assert res["targets_tested"][0]["status"] == "SKIPPED"


def test_real_get_target_still_reaches_sqlmap(monkeypatch):
    targets = [{"url": "http://t/real?x=1", "data": None, "extra_args": [], "label": "GET form"}]
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *a, **k: targets)
    sqlmap_calls, precheck_calls = _patch_common(monkeypatch, ["COMPLETED"], {"http://t/real?x=1": 200})

    res = asyncio.run(engines.run_sqlmap_multi("http://t", safe_mode="safe", timeout_seconds=1000))

    assert precheck_calls == ["http://t/real?x=1"]
    assert sqlmap_calls == ["http://t/real?x=1"]
    assert res["status"] == "COMPLETED"


def test_post_target_is_never_prechecked(monkeypatch):
    """Submitting a POST body has side effects: the precheck must not probe it at all."""
    targets = [{"url": "http://t/login", "data": "user=a&pass=b", "extra_args": [], "label": "POST form"}]
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *a, **k: targets)
    sqlmap_calls, precheck_calls = _patch_common(monkeypatch, ["COMPLETED"], {})

    res = asyncio.run(engines.run_sqlmap_multi("http://t", safe_mode="safe", timeout_seconds=1000))

    assert precheck_calls == []
    assert sqlmap_calls == ["http://t/login"]
    assert res["status"] == "COMPLETED"


def test_mixed_targets_skip_404_and_donate_time_to_the_rest(monkeypatch):
    """One 404'd GET target + one real GET target: only the real one reaches sqlmap, and the
    skipped slot's time is not wasted (dynamic per-target budget, not a fixed upfront split)."""
    targets = [
        {"url": "http://t/fake?x=1", "data": None, "extra_args": [], "label": "GET form"},
        {"url": "http://t/real?x=1", "data": None, "extra_args": [], "label": "GET form"},
    ]
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *a, **k: targets)
    sqlmap_calls, precheck_calls = _patch_common(
        monkeypatch, ["COMPLETED"],
        {"http://t/fake?x=1": 404, "http://t/real?x=1": 200},
    )

    res = asyncio.run(engines.run_sqlmap_multi("http://t", safe_mode="safe", timeout_seconds=1000))

    assert sqlmap_calls == ["http://t/real?x=1"]
    assert res["status"] == "PARTIAL"  # one real COMPLETED target + one correctly-skipped 404
    # targets_tested preserves input order; its "url" is redacted (query values -> [REDACTED]),
    # like every other entry in this field (see test_engine_diagnostics.py), so compare by path
    # prefix + status/order rather than the raw URL.
    tested = res["targets_tested"]
    assert len(tested) == 2
    assert tested[0]["url"].startswith("http://t/fake") and tested[0]["status"] == "SKIPPED"
    assert tested[1]["url"].startswith("http://t/real") and tested[1]["status"] == "COMPLETED"
