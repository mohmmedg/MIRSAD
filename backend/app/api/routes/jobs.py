from fastapi import APIRouter, Depends, HTTPException
from app.core.security import verify_api_key, require_analyst, require_viewer
from app.core.job_manager import job_manager
from app.schemas.jobs import JobSnapshot

router = APIRouter(prefix='/jobs', tags=['jobs'], dependencies=[Depends(verify_api_key), Depends(require_viewer)])

def _job(job_id):
    job = job_manager.get(job_id)
    if not job: raise HTTPException(status_code=404, detail='Job not found')
    return job

@router.get('/{job_id}', response_model=JobSnapshot)
async def get_job(job_id: str): return _job(job_id).snapshot()

@router.post('/{job_id}/pause', response_model=JobSnapshot, dependencies=[Depends(require_analyst)])
async def pause_job(job_id: str):
    if not await job_manager.pause(job_id): raise HTTPException(status_code=409, detail='Job is not running')
    return _job(job_id).snapshot()

@router.post('/{job_id}/resume', response_model=JobSnapshot, dependencies=[Depends(require_analyst)])
async def resume_job(job_id: str):
    if not await job_manager.resume(job_id): raise HTTPException(status_code=409, detail='Job is not paused')
    return _job(job_id).snapshot()

@router.post('/{job_id}/cancel', response_model=JobSnapshot, dependencies=[Depends(require_analyst)])
async def cancel_job(job_id: str):
    if not await job_manager.cancel(job_id): raise HTTPException(status_code=409, detail='Job cannot be cancelled')
    return _job(job_id).snapshot()
