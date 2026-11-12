from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.core.job_manager import job_manager
from app.core.security import verify_api_key, require_viewer
from app.schemas.network import ScanStatus

router=APIRouter(prefix="/scans",tags=["scans"],dependencies=[Depends(verify_api_key), Depends(require_viewer)])
class ScanStatusResponse(BaseModel):
    scan_id:str; scan_kind:str; target:str; status:ScanStatus; result:dict|None=None; error_message:str|None=None

@router.get("/{scan_id}/status",response_model=ScanStatusResponse)
async def get_scan_status(scan_id:str):
    job=job_manager.get(scan_id)
    if not job: raise HTTPException(status_code=404,detail="Scan not found")
    snap=job.snapshot()
    mapped={"pending":ScanStatus.PENDING,"running":ScanStatus.RUNNING,"paused":ScanStatus.RUNNING,"completed":ScanStatus.COMPLETED,"partial":ScanStatus.PARTIAL,"failed":ScanStatus.FAILED,"cancelled":ScanStatus.FAILED}
    return ScanStatusResponse(scan_id=snap.job_id,scan_kind=snap.job_type,target=snap.target,status=mapped[snap.status.value],result=snap.result,error_message=snap.error_message)
