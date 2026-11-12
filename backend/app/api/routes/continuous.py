from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.core.security import verify_api_key, verify_role
from app.core.auth import current_principal
from app.core.auth_context import tenant_context
from app.schemas.platform import FullScanRequest
from app.modules.continuous import continuous_scanner
from app.core.database import BASReplayRunRow, session_scope

async def _admin(x_api_key: str | None = Header(default=None)):
    await verify_role('analyst', x_api_key)
router=APIRouter(prefix='/continuous',tags=['continuous'],dependencies=[Depends(verify_api_key),Depends(_admin)])
class ScheduleRequest(BaseModel): request:FullScanRequest; interval_seconds:int=Field(default=3600,ge=300)
@router.post('/schedules',status_code=201)
async def create_schedule(body:ScheduleRequest,tenant_id:str|None=None):
    p=current_principal(); target=tenant_id or p.tenant_id
    if p.role!='owner' and target!=p.tenant_id: raise HTTPException(403,'Tenant admins can only manage their own organization')
    token=tenant_context.set(target)
    try: return await continuous_scanner.create(body.request,body.interval_seconds)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))
    finally: tenant_context.reset(token)

class AsnDiscoveryScheduleRequest(BaseModel):
    asn_or_org: str = Field(..., min_length=1, description="Root domain or organization name to periodically re-discover assets for (3.1)")
    interval_seconds: int = Field(default=86400, ge=300)

@router.post('/schedules/asn-discovery',status_code=201)
async def create_asn_discovery_schedule(body:AsnDiscoveryScheduleRequest,tenant_id:str|None=None):
    """3.1: recurring organization-wide new-asset discovery, distinct from an
    ordinary target-rescan schedule (see ContinuousScanner.create_asn_discovery)."""
    p=current_principal(); target=tenant_id or p.tenant_id
    if p.role!='owner' and target!=p.tenant_id: raise HTTPException(403,'Tenant admins can only manage their own organization')
    token=tenant_context.set(target)
    try: return await continuous_scanner.create_asn_discovery(body.asn_or_org,body.interval_seconds)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))
    finally: tenant_context.reset(token)

class BasReplayScheduleRequest(BaseModel):
    scan_id: str = Field(..., min_length=1, description="A completed scan whose template-backed findings should be periodically re-verified (4.4)")
    finding_ids: list[str] = Field(..., min_length=1)
    interval_seconds: int = Field(default=86400, ge=300)

@router.post('/schedules/bas-replay',status_code=201)
async def create_bas_replay_schedule(body:BasReplayScheduleRequest,tenant_id:str|None=None):
    """4.4: recurring safe replay of already-verified template findings to
    confirm they're still exploitable, or flag when they've been resolved.
    Advisory-only, non-destructive (see attack_simulation/simulator.py)."""
    p=current_principal(); target=tenant_id or p.tenant_id
    if p.role!='owner' and target!=p.tenant_id: raise HTTPException(403,'Tenant admins can only manage their own organization')
    token=tenant_context.set(target)
    try: return await continuous_scanner.create_bas_replay(body.scan_id,body.finding_ids,body.interval_seconds)
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))
    finally: tenant_context.reset(token)

@router.get('/schedules/{schedule_id}/bas-history')
async def get_bas_replay_history(schedule_id:str,limit:int=20):
    """4.4: durable replay history for one bas_replay schedule (see
    0016_bas_replay_history.sql) - the schedule's own `request.last_summary`
    only ever shows the most recent run; this returns the trend over time."""
    p=current_principal()
    async with session_scope(p.tenant_id) as db:
        rows=(await db.scalars(
            select(BASReplayRunRow)
            .where(BASReplayRunRow.tenant_id==p.tenant_id, BASReplayRunRow.schedule_id==schedule_id)
            .order_by(BASReplayRunRow.replayed_at.desc())
            .limit(max(1,min(limit,100)))
        )).all()
        return {"runs":[{
            "id":r.id,"scan_id":r.scan_id,"total_targets":r.total_targets,
            "still_live_count":r.still_live_count,"resolved_count":r.resolved_count,
            "unknown_count":r.unknown_count,"replayed_at":r.replayed_at.isoformat() if r.replayed_at else None,
        } for r in rows]}
@router.get('/schedules')
async def list_schedules(tenant_id:str|None=None):
    p=current_principal(); target=tenant_id or p.tenant_id
    if p.role!='owner' and target!=p.tenant_id: raise HTTPException(403,'Tenant admins can only manage their own organization')
    token=tenant_context.set(target)
    try: return {'schedules':await continuous_scanner.list()}
    finally: tenant_context.reset(token)
@router.delete('/schedules/{schedule_id}')
async def delete_schedule(schedule_id:str,tenant_id:str|None=None):
    p=current_principal(); target=tenant_id or p.tenant_id
    if p.role!='owner' and target!=p.tenant_id: raise HTTPException(403,'Tenant admins can only manage their own organization')
    token=tenant_context.set(target)
    try:
        item=await continuous_scanner.delete(schedule_id)
        if not item: raise HTTPException(status_code=404,detail='Schedule not found')
        return {'deleted':schedule_id}
    finally: tenant_context.reset(token)
