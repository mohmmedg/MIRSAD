from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core.architecture.manager import external_stage_status
from app.modules.external_scanners.engines import EXTERNAL_ENGINE_NAMES
from app.core.job_manager import JobRecord, _safe_execution_config, _stage_eta
from app.modules.technology.subdomain_discovery import _valid_hostname, discover_subdomains


def stage(sid, status="pending", progress=0, started=None, finished=None, **extra):
    return {"id": sid, "status": status, "progress": progress, "started_at": started, "finished_at": finished, **extra}


def test_external_eta_starts_with_sum_of_remaining_tool_timeouts():
    now = datetime.now(timezone.utc)
    stages = [stage("external_scanners", "running", 0, now.isoformat(), eta_hint_seconds=21600)]
    total, current = _stage_eta(stages, now + timedelta(seconds=1))
    assert current >= 21600 - 1
    assert total >= current


def test_external_eta_does_not_collapse_after_3000_seconds_at_two_percent():
    started = datetime.now(timezone.utc) - timedelta(seconds=3000)
    stages = [stage("external_scanners", "running", 2, started.isoformat(), eta_hint_seconds=21600)]
    total, current = _stage_eta(stages, datetime.now(timezone.utc))
    assert current >= 750
    assert total >= 750


def test_external_eta_floor_and_ema_when_observed_exceeds_prior():
    started = datetime.now(timezone.utc) - timedelta(seconds=1200)
    stages = [stage("web_crawl", "running", 50, started.isoformat(), eta_hint_seconds=100)]
    total, current = _stage_eta(stages, datetime.now(timezone.utc))
    assert current >= 300
    assert total >= current


def test_safe_execution_config_excludes_private_and_masks_sensitive():
    payload = {"target": "https://example.test", "_live_result": {"secret": "raw"}, "_execution_id": "id", "login_password": "secret", "auth_header": "Bearer secret", "max_pages": 80}
    out = _safe_execution_config(payload)
    assert not any(str(k).startswith("_") for k in out)
    assert out["login_password"] == "••••"
    assert out["auth_header"] == "••••"
    assert out["target"] == payload["target"]


def test_external_stage_terminal_states():
    ok = {n: {"status": "COMPLETED"} for n in EXTERNAL_ENGINE_NAMES}
    assert external_stage_status(ok)[0] == "completed"
    partial = dict(ok); partial["zap"] = {"status": "FAILED", "reason": "boom"}
    state, msg = external_stage_status(partial)
    assert state == "partial" and "failed=zap" in msg
    not_tested = dict(ok); not_tested["sqlmap"] = {"status": "NOT_TESTED", "reason": "no parameters"}
    state, msg = external_stage_status(not_tested)
    n = len(EXTERNAL_ENGINE_NAMES) - 1  # the NOT_TESTED engine is excluded from the count
    assert state == "completed" and f"{n}/{n} external detectors completed" in msg
    failed = {n: {"status": "FAILED", "reason": "boom"} for n in ok}
    assert external_stage_status(failed)[0] == "failed"
    disabled = {n: {"status": "DISABLED", "reason": "disabled"} for n in ok}
    assert external_stage_status(disabled)[0] == "skipped"


def test_subdomain_hostname_validation_and_ip_skip():
    assert _valid_hostname("portal.example.com")
    assert not _valid_hostname("127.0.0.0.1")
    assert not _valid_hostname("172.0.0.0.1")
    assert not _valid_hostname("123456")


@pytest.mark.asyncio
async def test_ip_target_skips_subdomain_discovery():
    assert await discover_subdomains("https://127.0.0.1") == []


def test_close_open_stages_default_behavior():
    job = object.__new__(JobRecord)
    stages = [{"id": "a", "status": "pending", "progress": 0}, {"id": "b", "status": "running", "progress": 50}, {"id": "c", "status": "completed", "progress": 100}]
    job._progress_meta = lambda: {"stages": stages}
    job.status = "completed"
    calls = []
    job.set_stage = lambda sid, status, **kwargs: calls.append((sid, status, kwargs["message"]))
    job.close_open_stages()
    assert [(x[0], x[1]) for x in calls] == [("a", "skipped"), ("b", "skipped")]

@pytest.mark.asyncio
async def test_after_sequence_returns_only_later_events(monkeypatch):
    from app.api.routes import jobs
    from types import SimpleNamespace
    captured = {}
    class Q:
        def filter(self, *args):
            captured.setdefault("filters", []).extend(args); return self
        def order_by(self, *args): return self
        def offset(self, value): captured["offset"] = value; return self
        def limit(self, value): captured["limit"] = value; return self
        def first(self): return SimpleNamespace(execution_id="e1")
        def all(self): return []
    class DB:
        def query(self, *args): return Q()
    class CM:
        def __enter__(self): return DB()
        def __exit__(self, *args): return False
    monkeypatch.setattr(jobs, "session_scope_sync", lambda: CM())
    monkeypatch.setattr(jobs, "with_db_retry", lambda f: f())
    monkeypatch.setattr(jobs, "_job", lambda job_id: object())
    token = jobs.tenant_context.set("legacy")
    try:
        await jobs.list_execution_events("j1", "e1", after_sequence=42, limit=100)
        assert captured["offset"] == 0
        assert captured["limit"] == 100
        assert captured["filters"]
    finally:
        jobs.tenant_context.reset(token)


@pytest.mark.asyncio
async def test_gemini_region_error_is_not_retried(monkeypatch):
    from app.modules.ai_analysis.analyzer import AIAnalyzer
    from app.core import config

    analyzer = object.__new__(AIAnalyzer)
    calls = {"n": 0}
    class Models:
        async def generate_content(self, **kwargs):
            calls["n"] += 1
            raise RuntimeError("400 FAILED_PRECONDITION: User location is not supported")
    analyzer._client = SimpleNamespace(aio=SimpleNamespace(models=Models()))
    result = await analyzer.validate_findings([SimpleNamespace(finding_id="f1", source_module="x", title="t", severity="Low", confidence=0.5, description="d", evidence=[], affected_asset="a", references=[])])
    assert result["reason_code"] == "gemini_region_unsupported"
    assert result["status"] == "fallback"
    assert calls["n"] == 1
