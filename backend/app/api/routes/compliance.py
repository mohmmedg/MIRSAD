from __future__ import annotations
import secrets
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.core.security import require_admin, require_analyst, verify_api_key
from app.core.auth import current_principal, require_step_up
from sqlalchemy import select
from app.core.database import session_scope, ComplianceControlRow, ComplianceAssessmentRow, CISecurityPolicyRow, utcnow
from app.modules.compliance import controls, assess, to_sarif, ci_gate

# See app/api/routes/admin.py for why verify_api_key must be declared
# explicitly here rather than relying on require_admin/require_analyst alone.
router=APIRouter(prefix="/compliance",tags=["compliance"],dependencies=[Depends(verify_api_key)])

class AssessmentRequest(BaseModel):
    findings:list[dict]=Field(default_factory=list)
    framework:str|None=None
    # Optional scan coverage (result.coverage from a UnifiedScanResult). When supplied,
    # a control with no matching findings can be resolved as a genuine PASS (capability
    # was tested and clean) instead of always falling back to NOT_ASSESSED.
    coverage:dict|None=None

class GateRequest(BaseModel):
    findings:list[dict]=Field(default_factory=list)
    policy:dict|None=None
    coverage:dict|None=None

class CIPolicyUpdate(BaseModel):
    critical_fail:int=Field(default=0,ge=0,le=10000)
    high_fail:int=Field(default=0,ge=0,le=10000)
    medium_fail:int=Field(default=0,ge=0,le=10000)
    enabled:bool=True

@router.get("/frameworks")
async def frameworks(_:object=Depends(require_analyst)):
    fs=sorted({c.framework for c in controls()})
    return {"frameworks":fs}

@router.get("/controls")
async def list_controls(framework:str|None=None,_:object=Depends(require_analyst)):
    p=current_principal()
    base=controls(framework)
    async with session_scope(p.tenant_id) as db:
        rows={r.control_id:r for r in (await db.scalars(select(ComplianceControlRow).where(ComplianceControlRow.tenant_id==p.tenant_id))).all()}
    out=[]
    for c in base:
        r=rows.get(c.control_id)
        out.append({"control_id":c.control_id,"framework":c.framework,"title":c.title,"description":c.description,
                    "tags":list(c.tags),"max_severity":c.max_severity,"enabled":True if r is None else r.enabled})
    return {"controls":out}

@router.patch("/controls/{control_id}")
async def set_control(control_id:str,enabled:bool,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); c=next((x for x in controls() if x.control_id==control_id),None)
    if not c: raise HTTPException(404,"Control not found")
    async with session_scope(p.tenant_id) as db:
        row=await db.scalar(select(ComplianceControlRow).where(ComplianceControlRow.tenant_id==p.tenant_id, ComplianceControlRow.control_id==control_id))
        if not row:
            row=ComplianceControlRow(control_id=c.control_id,tenant_id=p.tenant_id,framework=c.framework,title=c.title,description=c.description,tags=list(c.tags),max_severity=c.max_severity,enabled=enabled,updated_at=utcnow()); db.add(row)
        else: row.enabled=enabled; row.updated_at=utcnow()
    return {"control_id":control_id,"enabled":enabled}

@router.post("/assess",status_code=201)
async def run_assessment(body:AssessmentRequest,_:object=Depends(require_analyst)):
    p=current_principal()
    result=assess(body.findings,body.framework,body.coverage)
    # honor tenant-specific disabled controls
    async with session_scope(p.tenant_id) as db:
        disabled={r.control_id for r in (await db.scalars(select(ComplianceControlRow).where(ComplianceControlRow.tenant_id==p.tenant_id,ComplianceControlRow.enabled.is_(False)))).all()}
        if disabled:
            result["controls"]=[x for x in result["controls"] if x["control_id"] not in disabled]
            result["failed"]=sum(x["status"]=="fail" for x in result["controls"])
            result["passed"]=sum(x["status"] in {"pass","pass_with_observations"} for x in result["controls"])
            result["score"]=round(100*result["passed"]/max(1,len(result["controls"])),1)
        row=ComplianceAssessmentRow(assessment_id="cmp_"+secrets.token_hex(12),tenant_id=p.tenant_id,framework=result["framework"],score=result["score"],passed=result["passed"],failed=result["failed"],controls=result["controls"],created_at=utcnow()); db.add(row)
        result["assessment_id"]=row.assessment_id
    return result

@router.get("/assessments")
async def history(limit:int=20,_:object=Depends(require_analyst)):
    p=current_principal()
    async with session_scope(p.tenant_id) as db:
        rows=(await db.scalars(select(ComplianceAssessmentRow).where(ComplianceAssessmentRow.tenant_id==p.tenant_id).order_by(ComplianceAssessmentRow.created_at.desc()).limit(min(limit,100)))).all()
    return {"assessments":[{"assessment_id":r.assessment_id,"framework":r.framework,"score":r.score,"passed":r.passed,"failed":r.failed,"created_at":r.created_at.isoformat()} for r in rows]}

@router.post("/sarif")
async def sarif(body:AssessmentRequest,_:object=Depends(require_analyst)):
    return to_sarif(body.findings)

@router.get("/ci-policy")
async def get_ci_policy(_:object=Depends(require_analyst)):
    p=current_principal()
    async with session_scope(p.tenant_id) as db:
        r=await db.get(CISecurityPolicyRow,p.tenant_id)
        if not r:
            return {"critical_fail":0,"high_fail":0,"medium_fail":0,"enabled":True}
        return {"critical_fail":r.critical_fail,"high_fail":r.high_fail,"medium_fail":r.medium_fail,"enabled":r.enabled}

@router.put("/ci-policy")
async def update_ci_policy(body:CIPolicyUpdate,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal()
    async with session_scope(p.tenant_id) as db:
        r=await db.get(CISecurityPolicyRow,p.tenant_id)
        if not r:
            r=CISecurityPolicyRow(tenant_id=p.tenant_id,critical_fail=body.critical_fail,high_fail=body.high_fail,medium_fail=body.medium_fail,enabled=body.enabled,updated_at=utcnow()); db.add(r)
        else:
            r.critical_fail=body.critical_fail; r.high_fail=body.high_fail; r.medium_fail=body.medium_fail; r.enabled=body.enabled; r.updated_at=utcnow()
    return body.model_dump()

@router.post("/ci-gate")
async def security_gate(body:GateRequest,_:object=Depends(require_analyst)):
    p=current_principal()
    async with session_scope(p.tenant_id) as db:
        r=await db.get(CISecurityPolicyRow,p.tenant_id)
        policy={"critical_fail":r.critical_fail,"high_fail":r.high_fail,"medium_fail":r.medium_fail,"enabled":r.enabled} if r else {"critical_fail":0,"high_fail":0,"medium_fail":0,"enabled":True}
    if not policy.get("enabled",True): return {"passed":True,"exit_code":0,"disabled":True,"counts":{},"failures":[]}
    return ci_gate(body.findings,policy,body.coverage)
