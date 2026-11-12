import asyncio
import pytest
from app.core.job_manager import JobManager
from app.core.auth_context import tenant_context
from app.schemas.jobs import JobStatus

@pytest.mark.asyncio
async def test_job_lifecycle_pause_resume_and_completion():
    jm = JobManager()
    gate = asyncio.Event()
    async def runner(job):
        job.progress = 25
        await job.checkpoint('network')
        await gate.wait()
        job.progress = 90
        await job.checkpoint('finalize')
        return {'ok': True}
    job = await jm.create('full', 'example.com', runner)
    await asyncio.sleep(0)
    assert job.status == JobStatus.RUNNING
    assert await jm.pause(job.job_id) is True
    await asyncio.sleep(0)
    assert job.status == JobStatus.PAUSED
    assert await jm.resume(job.job_id) is True
    gate.set()
    await job.task
    assert job.status == JobStatus.COMPLETED
    assert job.progress == 100
    assert job.snapshot().result == {'ok': True}

@pytest.mark.asyncio
async def test_job_cancel_is_terminal():
    jm = JobManager()
    async def runner(job):
        await asyncio.sleep(10)
    job = await jm.create('full', 'example.com', runner)
    await asyncio.sleep(0)
    assert await jm.cancel(job.job_id) is True
    await asyncio.sleep(0)
    assert job.status == JobStatus.CANCELLED

@pytest.mark.asyncio
async def test_unknown_job_operations_are_safe():
    jm = JobManager()
    assert jm.get('missing') is None
    assert await jm.pause('missing') is False
    assert await jm.resume('missing') is False
    assert await jm.cancel('missing') is False


@pytest.mark.asyncio
async def test_real_tenant_can_create_multiple_scan_jobs_without_a_quota():
    """Scan creation is not blocked by tenant concurrency/quota policy."""
    token = tenant_context.set('job-manager-regression-tenant')
    try:
        jm = JobManager()

        async def runner(job):
            return {'ok': True}

        jobs = [await jm.create('full', f'example-{i}.com', runner) for i in range(5)]
        await asyncio.gather(*(job.task for job in jobs))
        assert all(job.status == JobStatus.COMPLETED for job in jobs)
    finally:
        tenant_context.reset(token)
