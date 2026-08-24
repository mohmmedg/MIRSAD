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
