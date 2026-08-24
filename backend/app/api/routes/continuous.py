from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from app.core.security import verify_api_key, verify_role
from app.schemas.platform import FullScanRequest
from app.modules.continuous import continuous_scanner

async def _admin(x_api_key: str | None = Header(default=None)):
    await verify_role('analyst', x_api_key)
router=APIRouter(prefix='/continuous',tags=['continuous'],dependencies=[Depends(verify_api_key),Depends(_admin)])
class ScheduleRequest(BaseModel): request:FullScanRequest; interval_seconds:int=Field(default=3600,ge=300)
@router.post('/schedules',status_code=201)
async def create_schedule(body:ScheduleRequest):
    try:return continuous_scanner.create(body.request,body.interval_seconds)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))
@router.get('/schedules')
async def list_schedules(): return {'schedules':continuous_scanner.list()}
@router.delete('/schedules/{schedule_id}')
async def delete_schedule(schedule_id:str):
    item=continuous_scanner.delete(schedule_id)
    if not item: raise HTTPException(status_code=404,detail='Schedule not found')
    return {'deleted':schedule_id}
