import pytest
from app.core.job_manager import JobManager
from app.schemas.jobs import JobStatus

@pytest.mark.asyncio
async def test_job_state_is_durable_across_manager_instances():
    first=JobManager()
    job=await first.create("full","example.com",start=False,payload={"target":"example.com"})
    job.progress=37
    job.log("durable")
    second=JobManager()
    restored=second.get(job.job_id)
    assert restored is not None
    snap=restored.snapshot()
    assert snap.progress == 37
    assert "durable" in snap.logs[-1]
    assert snap.status == JobStatus.PENDING


def test_mutating_job_routes_require_authentication_before_scope_check():
    from app.api.routes.jobs import router
    from app.core.security import verify_api_key
    from fastapi.routing import APIRoute

    expected = {"/jobs/{job_id}/pause", "/jobs/{job_id}/resume", "/jobs/{job_id}/cancel"}
    routes = {r.path: r for r in router.routes if isinstance(r, APIRoute) and r.path in expected}
    assert set(routes) == expected
    for route in routes.values():
        dependency_callables = {d.call for d in route.dependant.dependencies}
        assert verify_api_key in dependency_callables

