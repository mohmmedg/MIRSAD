"""Supabase egress reduction: light row reads, Redis-first live result, `since` short-circuit."""
import pytest
from sqlalchemy import event

import app.core.job_manager as jmod
from app.core.database import engine, JobRow
from app.core.job_manager import JobManager, read_live_result_cached
from app.schemas.jobs import JobStatus


class FakeRedis:
    def __init__(self): self.d = {}
    def get(self, k): return self.d.get(k)
    def setex(self, k, ttl, v): self.d[k] = v


@pytest.fixture
def fake_redis(monkeypatch):
    r = FakeRedis()
    monkeypatch.setattr(jmod, "_hot_cache", lambda: r)
    monkeypatch.setattr(jmod, "_hot_cache_disabled_until", 0.0)
    return r


def _stmts(fn):
    seen = []
    def before(conn, cursor, statement, *a): seen.append(statement)
    event.listen(engine, "before_cursor_execute", before)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", before)
    return seen


@pytest.mark.asyncio
async def test_light_reads_never_select_result_or_payload(fake_redis):
    jm = JobManager()
    job = await jm.create("full", "example.com", None, start=False)
    def reads():
        assert jm.get(job.job_id) is not None
        job._row(defer_result=True, defer_payload=True).progress
        assert job.progress == 0
    sql = " ".join(_stmts(reads)).lower()
    assert "scan_jobs.result" not in sql and "scan_jobs.payload" not in sql


@pytest.mark.asyncio
async def test_live_result_goes_to_redis_not_db_until_terminal(fake_redis):
    jm = JobManager()
    job = await jm.create("full", "example.com", None, start=False)
    job.publish_partial_result(web={"a": 1})
    job.publish_partial_result(network={"b": 2})
    job.flush_writes()
    live = read_live_result_cached("legacy", job.job_id)
    assert live["web_scan"] == {"a": 1} and live["network_scan"] == {"b": 2} and live["updated_at"]
    assert "_live_result" not in (job._row().payload or {})  # not in the durable row yet
    job.status = JobStatus.COMPLETED
    assert (job._row().payload or {}).get("_live_result", {}).get("web_scan") == {"a": 1}


@pytest.mark.asyncio
async def test_live_result_falls_back_to_db_without_redis(monkeypatch):
    monkeypatch.setattr(jmod, "_hot_cache", lambda: None)
    jm = JobManager()
    job = await jm.create("full", "example.com", None, start=False)
    job.publish_partial_result(web={"a": 1})
    job.flush_writes()
    assert job._row().payload["_live_result"]["web_scan"] == {"a": 1}


@pytest.mark.asyncio
async def test_live_result_endpoint_since_unchanged(fake_redis):
    from app.api.routes import jobs as routes
    jm = JobManager()
    job = await jm.create("full", "example.com", None, start=False)
    monkey_job = jm  # route uses global job_manager; point it at ours
    routes.job_manager = jm
    job.publish_partial_result(web={"a": 1}); job.flush_writes()
    full = await routes.live_result(job.job_id)
    assert full["web_scan"] == {"a": 1}
    again = await routes.live_result(job.job_id, since=full["updated_at"])
    assert again == {"unchanged": True, "updated_at": full["updated_at"]}
