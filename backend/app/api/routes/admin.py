from __future__ import annotations

import hashlib
import logging
import secrets

import httpx
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func

from app.core.auth import current_principal, invalidate_principal_cache, require_step_up
from app.core.config import settings
from app.core.database import (AuditLogRow, UserRow, session_scope, utcnow,
    AdminSettingRow, FeatureFlagRow, ApiKeyRow, RefreshTokenRow, TenantRow)
from app.core.security import require_admin, verify_api_key
from app.core.security_events import record_security_event
from app.core.policy_enforcement import DEFAULT_AI, DEFAULT_SCAN, DEFAULT_SECURITY, validate_policy

# CRITICAL: every other router in this codebase pairs its role check with
# Depends(verify_api_key) (see network.py, web.py, scans.py, platform.py,
# jobs.py, api_security.py, analysis.py, continuous.py). require_admin() by
# itself never reads the Authorization/X-API-Key headers -- it only looks at
# whatever Principal a *prior* dependency already put in the request-scoped
# ContextVar. Without verify_api_key running first on THIS router, admin
# endpoints depended entirely on ambient/previously-set context instead of
# authenticating the current request's own credentials. Always declare
# verify_api_key explicitly so every request is authenticated from its own
# headers, independent of any other dependency's side effects.
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(verify_api_key)])
logger = logging.getLogger(__name__)
ROLES={"viewer","analyst","admin","owner"}
DEFAULT_NOTIFICATIONS={"critical_findings":True,"scan_failures":True,"worker_down":True,"suspicious_login":True,"api_key_expiring":True}
DEFAULT_FLAGS={"gemini_intelligence":True,"continuous_scanning":False,"cloud_exposure":False,"js_intelligence":True,"graphql_scanner":True,"ci_cd":True,"webhooks":False}
ALLOWED_API_KEY_SCOPES={"scanner:read","scanner:run","scanner:pause","scanner:cancel","reports:read","finding:lifecycle","admin:*"}
PERMISSIONS={"users.read","users.create","users.update","users.delete","users.write","roles.read","roles.write","sessions.read","sessions.revoke","api_keys.read","api_keys.create","api_keys.revoke","security.read","security.write","scans.manage","jobs.manage","audit.read","features.manage","tenant.manage","ai.manage","notifications.manage","health.read","backup.read"}

class AdminUser(BaseModel):
    user_id:str; email:str; role:str; is_active:bool; created_at:str; tenant_id:str; tenant_name:str
class UserListResponse(BaseModel): users:list[AdminUser]; total:int
class UserUpdateRequest(BaseModel): role:str|None=None; is_active:bool|None=None
class UserCreateRequest(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    tenant_id: str | None = None
class UserDeleteResponse(BaseModel):
    ok: bool
    user_id: str
class PasswordResetRequest(BaseModel):
    new_password: str|None = Field(default=None, min_length=12, max_length=128)
class PasswordResetResponse(BaseModel):
    ok: bool
    user_id: str
    email: str
    new_password: str
class PolicyUpdate(BaseModel):
    values:dict[str,object]=Field(default_factory=dict)
    tenant_id:str|None=None
class FeatureUpdate(BaseModel):
    flags:dict[str,bool]=Field(default_factory=dict)
    tenant_id:str|None=None
class ApiKeyCreate(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    scopes:list[str]=Field(default_factory=list)
    expires_in_days:int|None=Field(default=None,ge=1,le=3650)
    tenant_id:str|None=None

async def _target_tenant(p, requested: str | None = None, *, required_for_owner: bool = False) -> str:
    requested = (requested or "").strip() or None
    if p.role != "owner":
        if requested and requested != p.tenant_id:
            raise HTTPException(403, "Tenant admins can only manage their own organization")
        return p.tenant_id
    if requested:
        async with session_scope(None) as db:
            if not await db.get(TenantRow, requested):
                raise HTTPException(404, "Organization not found")
        return requested
    if required_for_owner:
        raise HTTPException(400, "Owner must select an organization")
    return p.tenant_id

@router.get("/tenants")
async def list_tenants(_:object=Depends(require_admin)):
    p=current_principal()
    async with session_scope(None) as db:
        rows=(await db.scalars(select(TenantRow).order_by(TenantRow.name.asc()))).all() if p.role=="owner" else [await db.get(TenantRow,p.tenant_id)]
    rows=[r for r in rows if r is not None]
    return {"tenants":[{"tenant_id":r.tenant_id,"name":r.name,"created_at":r.created_at.isoformat()} for r in rows]}

def _validate_role(role:str)->str:
    v=role.strip().lower()
    if v not in ROLES: raise HTTPException(422,"Invalid role")
    return v
def _can_manage(actor:str,target:str,new:str|None)->bool:
    if actor=="owner": return target!="owner" and new!="owner"
    return target in {"viewer","analyst"} and new!="owner"
def _audit(db,tenant,event,target=None,data=None):
    db.add(AuditLogRow(id=secrets.token_hex(16),tenant_id=tenant,event=event,target=target,data=data or {},created_at=utcnow()))
async def _setting(db,tenant):
    row=await db.get(AdminSettingRow,tenant)
    if not row:
        row=AdminSettingRow(tenant_id=tenant,security_policy=DEFAULT_SECURITY.copy(),scan_policy=DEFAULT_SCAN.copy(),ai_policy=DEFAULT_AI.copy(),notification_policy=DEFAULT_NOTIFICATIONS.copy(),updated_at=utcnow()); db.add(row); await db.flush()
    return row


def _supabase_admin_headers() -> dict[str, str]:
    key = settings.SUPABASE_SERVICE_ROLE_KEY
    if not settings.SUPABASE_URL or not key:
        raise HTTPException(
            status_code=503,
            detail="Supabase service-role administration is not configured",
        )
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


def _supabase_admin_url(path: str) -> str:
    if not settings.SUPABASE_URL:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    return f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/admin/{path.lstrip('/')}"


def _supabase_create_user(email: str, password: str, tenant_id: str) -> str:
    payload = {
        "email": email,
        "password": password,
        "email_confirm": True,
        "user_metadata": {"tenant_id": tenant_id},
    }
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                _supabase_admin_url("users"),
                headers=_supabase_admin_headers(),
                json=payload,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Unable to reach Supabase Auth") from exc

    data = response.json() if response.content else {}
    if response.status_code >= 400:
        message = data.get("msg") or data.get("message") or data.get("error") or "Supabase user creation failed"
        raise HTTPException(status_code=409 if response.status_code in {400,409,422} else 502, detail=message)

    user_id = str((data.get("user") or data).get("id") or "").strip()
    if not user_id:
        raise HTTPException(status_code=502, detail="Supabase created the account without returning a user id")
    return user_id


def _supabase_update_user_password(user_id: str, password: str) -> None:
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.put(
                _supabase_admin_url(f"users/{user_id}"),
                headers=_supabase_admin_headers(),
                json={"password": password},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Unable to reach Supabase Auth") from exc

    if response.status_code >= 400:
        data = response.json() if response.content else {}
        message = data.get("msg") or data.get("message") or data.get("error") or "Supabase password update failed"
        raise HTTPException(status_code=409 if response.status_code in {400,409,422} else 502, detail=message)


def _supabase_delete_user(user_id: str) -> None:
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.delete(
                _supabase_admin_url(f"users/{user_id}"),
                headers=_supabase_admin_headers(),
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Unable to reach Supabase Auth") from exc

    if response.status_code >= 400:
        data = response.json() if response.content else {}
        message = data.get("msg") or data.get("message") or data.get("error") or "Supabase user deletion failed"
        raise HTTPException(status_code=502, detail=message)
async def _flags(db,tenant):
    row=await db.get(FeatureFlagRow,tenant)
    if not row:
        row=FeatureFlagRow(tenant_id=tenant,flags=DEFAULT_FLAGS.copy(),updated_at=utcnow()); db.add(row); await db.flush()
    return row

@router.get("/overview")
async def overview(tenant_id:str|None=Query(default=None),_:object=Depends(require_admin)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        total=await db.scalar(select(func.count()).select_from(UserRow).where(UserRow.tenant_id==target)) or 0
        active=await db.scalar(select(func.count()).select_from(UserRow).where(UserRow.tenant_id==target,UserRow.is_active.is_(True))) or 0
        admins=await db.scalar(select(func.count()).select_from(UserRow).where(UserRow.tenant_id==target,UserRow.role.in_(["admin","owner"]))) or 0
        keys=await db.scalar(select(func.count()).select_from(ApiKeyRow).where(ApiKeyRow.tenant_id==target,ApiKeyRow.revoked.is_(False))) or 0
        sessions=await db.scalar(select(func.count()).select_from(RefreshTokenRow).where(RefreshTokenRow.tenant_id==target,RefreshTokenRow.revoked.is_(False),RefreshTokenRow.expires_at>utcnow())) or 0
        JobRow=__import__('app.core.database',fromlist=['JobRow']).JobRow
        jobs=await db.scalar(select(func.count()).select_from(JobRow).where(JobRow.tenant_id==target,JobRow.status.in_(["queued","running"]))) or 0
    return {"tenant_id":target,"actor":p.as_dict(),"users":{"total":total,"active":active,"admins":admins},"api_keys":keys,"active_sessions":sessions,"active_jobs":jobs,"supabase_admin_sync":bool(settings.SUPABASE_SERVICE_ROLE_KEY),"environment":settings.ENVIRONMENT}

@router.get("/users",response_model=UserListResponse)
async def list_users(_:object=Depends(require_admin),search:str|None=Query(default=None,max_length=200),tenant_id:str|None=Query(default=None)):
    p=current_principal()
    # Owner must explicitly select the organization for every tenant-scoped
    # users operation. This keeps the Owner UI platform-wide in capability,
    # but tenant-scoped in the data shown on screen. Regular admins remain
    # locked to their own organization.
    target = await _target_tenant(p, tenant_id, required_for_owner=p.role == "owner")
    async with session_scope(target) as db:
        stmt=select(UserRow).where(UserRow.tenant_id==target).order_by(UserRow.created_at.asc())
        if search: stmt=stmt.where(UserRow.email.ilike(f"%{search.strip()}%"))
        users=(await db.scalars(stmt)).all()
    async with session_scope(None) as tenant_db:
        tenant_rows = (await tenant_db.scalars(select(TenantRow).where(TenantRow.tenant_id.in_({u.tenant_id for u in users})))).all()
        tenant_names = {t.tenant_id: t.name for t in tenant_rows}
    return UserListResponse(users=[AdminUser(user_id=u.user_id,email=u.email,role=u.role,is_active=u.is_active,created_at=u.created_at.isoformat(),tenant_id=u.tenant_id,tenant_name=tenant_names.get(u.tenant_id, u.tenant_id)) for u in users],total=len(users))

@router.post("/users",response_model=AdminUser,status_code=201)
async def create_user(body:UserCreateRequest,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); email=body.email.strip().lower()
    if not email: raise HTTPException(422,"Email is required")
    target=await _target_tenant(p,body.tenant_id,required_for_owner=True)
    async with session_scope(target) as db:
        if await db.scalar(select(UserRow).where(UserRow.email==email)):
            raise HTTPException(409,"An account with this email already exists")
    user_id=_supabase_create_user(email,body.password,target)
    try:
        async with session_scope(target) as db:
            if await db.get(UserRow,user_id): raise HTTPException(409,"This Supabase user is already provisioned")
            user=UserRow(user_id=user_id,tenant_id=target,email=email,password_hash="",role="viewer",is_active=True,created_at=utcnow())
            db.add(user); _audit(db,target,"admin.user.created",user_id,{"actor":p.user_id,"role":"viewer"})
            tenant_row=await db.get(TenantRow,target)
            result=AdminUser(user_id=user.user_id,email=user.email,role=user.role,is_active=user.is_active,created_at=user.created_at.isoformat(),tenant_id=target,tenant_name=tenant_row.name if tenant_row else target)
    except Exception:
        try: _supabase_delete_user(user_id)
        except HTTPException:
            logger.warning(
                "Failed to roll back Supabase user %s after local provisioning error; "
                "an orphaned Supabase account may now exist for tenant %s",
                user_id, target,
            )
        raise
    await record_security_event(tenant_id=target,event_type="admin.user.created",actor_user_id=p.user_id,target=user_id,data={"email":email,"role":"viewer"})
    return result

@router.patch("/users/{user_id}",response_model=AdminUser)
async def update_user(user_id:str,body:UserUpdateRequest,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal()
    if body.role is None and body.is_active is None: raise HTTPException(422,"No changes supplied")
    if user_id==p.user_id and body.is_active is False: raise HTTPException(400,"You cannot deactivate your own account")
    role=_validate_role(body.role) if body.role is not None else None
    target_scope = await _target_tenant(p, tenant_id, required_for_owner=p.role == "owner")
    async with session_scope(target_scope) as db:
        user=await db.get(UserRow,user_id)
        if not user or user.tenant_id != target_scope: raise HTTPException(404,"User not found in selected organization")
        if not _can_manage(p.role,user.role,role): raise HTTPException(403,"You cannot modify this user's role or account")
        target=user.tenant_id
        if role is not None: user.role=role
        if body.is_active is not None: user.is_active=body.is_active
        changed_role=role is not None
        if changed_role or body.is_active is not None:
            user.security_changed_at=utcnow()
            policy=((await _setting(db,target)).security_policy or {})
            if policy.get("force_logout_on_role_change",True) and (changed_role or body.is_active is False):
                from sqlalchemy import update as _sa_update
                await db.execute(_sa_update(RefreshTokenRow).where(RefreshTokenRow.user_id==user.user_id,RefreshTokenRow.tenant_id==target).values(revoked=True))
        _audit(db,target,"admin.user.updated",user.user_id,{"actor":p.user_id,"role":user.role,"is_active":user.is_active})
        tenant_row=await db.get(TenantRow,target)
        result=AdminUser(user_id=user.user_id,email=user.email,role=user.role,is_active=user.is_active,created_at=user.created_at.isoformat(),tenant_id=target,tenant_name=tenant_row.name if tenant_row else target)
        user_id_out,user_role_out=user.user_id,user.role
    invalidate_principal_cache()  # role/active changes must apply immediately, not after the auth-cache TTL
    if changed_role: await record_security_event(tenant_id=target,event_type="admin.user.role_changed",actor_user_id=p.user_id,target=user_id_out,data={"new_role":user_role_out})
    elif body.is_active is False: await record_security_event(tenant_id=target,event_type="admin.user.disabled",actor_user_id=p.user_id,target=user_id_out,data={"role":user_role_out})
    return result

@router.post("/users/{user_id}/reset-password",response_model=PasswordResetResponse)
async def reset_user_password(user_id:str,body:PasswordResetRequest,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal()
    # The owner may reset the password of any account, on any tenant,
    # including other admins. A regular admin is still confined to its own
    # tenant and can never reset another admin's (or the owner's) password --
    # this mirrors the exact same hierarchy _can_manage() already enforces
    # for role changes.
    target_scope = await _target_tenant(p, tenant_id, required_for_owner=p.role == "owner")
    async with session_scope(target_scope) as db:
        user=await db.get(UserRow,user_id)
        if not user or user.tenant_id != target_scope:
            raise HTTPException(404,"User not found in selected organization")
        if not _can_manage(p.role,user.role,None):
            raise HTTPException(403,"You cannot reset this user's password")
        target_tenant,target_email=user.tenant_id,user.email

    new_password=(body.new_password or secrets.token_urlsafe(18))[:128]
    if len(new_password)<12:
        raise HTTPException(422,"Password must be at least 12 characters")

    _supabase_update_user_password(user_id,new_password)

    from sqlalchemy import update as _sa_update
    async with session_scope(target_tenant) as db:
        await db.execute(_sa_update(RefreshTokenRow).where(RefreshTokenRow.user_id==user_id,RefreshTokenRow.tenant_id==target_tenant).values(revoked=True))
        u=await db.get(UserRow,user_id)
        if u: u.security_changed_at=utcnow()
        _audit(db,target_tenant,"admin.user.password_reset",user_id,{"actor":p.user_id,"email":target_email})

    await record_security_event(tenant_id=target_tenant,event_type="admin.user.password_reset",actor_user_id=p.user_id,target=user_id,data={"email":target_email})
    return PasswordResetResponse(ok=True,user_id=user_id,email=target_email,new_password=new_password)

@router.delete("/users/{user_id}",response_model=UserDeleteResponse)
async def delete_user(user_id:str,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal()
    if user_id == p.user_id:
        raise HTTPException(400,"You cannot delete your own account")

    # Owner can delete from any organization, but the UI-selected
    # organization is still enforced so an action cannot accidentally target
    # a user from another organization. Tenant admins remain tenant-scoped.
    target_scope = await _target_tenant(p, tenant_id, required_for_owner=p.role == "owner")

    async with session_scope(target_scope) as db:
        user=await db.get(UserRow,user_id)
        if not user or user.tenant_id != target_scope:
            raise HTTPException(404,"User not found in selected organization")
        if user.role == "owner":
            raise HTTPException(403,"The owner account cannot be deleted")
        if p.role != "owner" and user.role == "admin":
            raise HTTPException(403,"Only the owner can delete an administrator")
        target_email,target_tenant_id=user.email,user.tenant_id

    from sqlalchemy import update as _sa_update
    # Disable the local account and revoke every session first.
    async with session_scope(target_tenant_id) as db:
        user=await db.get(UserRow,user_id)
        if not user or user.tenant_id != target_tenant_id:
            raise HTTPException(404,"User not found")
        user.is_active=False
        user.security_changed_at=utcnow()
        await db.execute(_sa_update(RefreshTokenRow).where(RefreshTokenRow.user_id==user_id).values(revoked=True))

    invalidate_principal_cache()  # the account is now disabled: drop any cached session immediately
    # Remove the identity from Auth.
    _supabase_delete_user(user_id)

    # Remove the corresponding application user row as well. This is
    # intentionally done after Auth deletion so an Auth failure cannot
    # silently remove a still-valid login from the application database.
    async with session_scope(target_tenant_id) as db:
        user=await db.get(UserRow,user_id)
        if user:
            await db.delete(user)
        _audit(db,target_tenant_id,"admin.user.deleted",user_id,{"actor":p.user_id,"email":target_email})

    await record_security_event(tenant_id=target_tenant_id,event_type="admin.user.deleted",actor_user_id=p.user_id,target=user_id,data={"email":target_email})
    return UserDeleteResponse(ok=True,user_id=user_id)

@router.get("/audit")
async def audit_log(_:object=Depends(require_admin),limit:int=Query(default=100,ge=1,le=500),event:str|None=None,tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        stmt=select(AuditLogRow).where(AuditLogRow.tenant_id==target).order_by(AuditLogRow.created_at.desc()).limit(limit)
        if event: stmt=stmt.where(AuditLogRow.event==event)
        rows=(await db.scalars(stmt)).all()
    return {"events":[{"id":r.id,"event":r.event,"target":r.target,"data":r.data,"created_at":r.created_at.isoformat()} for r in rows]}

@router.get("/policies")
async def get_policies(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        r=await _setting(db,target)
        return {"security":r.security_policy,"scan":r.scan_policy,"ai":r.ai_policy,"notifications":r.notification_policy,"updated_at":r.updated_at.isoformat()}

@router.put("/policies/{kind}")
async def update_policy(kind:str,body:PolicyUpdate,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    if kind not in {"security","scan","ai","notifications"}: raise HTTPException(404,"Unknown policy")
    values=validate_policy(kind, body.values)
    if kind == "security" and body.values.get("require_mfa") is False:
        raise HTTPException(403, "MFA cannot be disabled for privileged administration")
    if kind == "scan" and values.get("enforce_target_scope") is False and settings.ENVIRONMENT == "production":
        raise HTTPException(403, "Target scope enforcement cannot be disabled in production")
    if kind == "ai" and values.get("enabled") is False and settings.ENVIRONMENT == "production":
        # AI may be disabled intentionally in production; this branch exists to
        # make the decision explicit and auditable rather than silently ignore it.
        pass
    p=current_principal(); target=await _target_tenant(p,body.tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        r=await _setting(db,target); old=getattr(r,f"{kind}_policy") or {}; merged={**old,**values}; setattr(r,f"{kind}_policy",merged); r.updated_at=utcnow(); _audit(db,target,f"admin.policy.{kind}",kind,{"actor":p.user_id,"changed":list(values)})
    await record_security_event(tenant_id=target,event_type="admin.policy.changed",actor_user_id=p.user_id,target=kind,data={"changed":list(values)})
    return merged

@router.get("/features")
async def get_features(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db: return (await _flags(db,target)).flags
@router.put("/features")
async def update_features(body:FeatureUpdate,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,body.tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        r=await _flags(db,target); r.flags={**r.flags,**body.flags}; r.updated_at=utcnow(); _audit(db,target,"admin.features.updated","features",{"actor":p.user_id,"changed":list(body.flags)}); return r.flags

@router.get("/permissions")
async def permissions(_:object=Depends(require_admin)):
    return {"permissions":sorted(PERMISSIONS),"role_matrix":{"owner":sorted(PERMISSIONS),"admin":sorted(PERMISSIONS-{"tenant.manage","backup.read"}),"analyst":sorted({"users.read","roles.read","scans.manage","audit.read","health.read"}),"viewer":sorted({"health.read"})}}

@router.get("/sessions")
async def sessions(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        rows=(await db.scalars(select(RefreshTokenRow).where(RefreshTokenRow.tenant_id==target).order_by(RefreshTokenRow.created_at.desc()).limit(200))).all()
        return {"sessions":[{"id":r.token_hash[:12],"user_id":r.user_id,"created_at":r.created_at.isoformat(),"expires_at":r.expires_at.isoformat(),"revoked":r.revoked} for r in rows]}
@router.post("/sessions/{token_id}/revoke")
async def revoke_session(token_id:str,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        rows=(await db.scalars(select(RefreshTokenRow).where(RefreshTokenRow.tenant_id==target))).all()
        r=next((x for x in rows if x.token_hash.startswith(token_id)),None)
        if not r: raise HTTPException(404,"Session not found")
        r.revoked=True; _audit(db,target,"admin.session.revoked",r.user_id,{"actor":p.user_id}); return {"ok":True}
@router.post("/sessions/revoke-all")
async def revoke_all_sessions(tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        rows=(await db.scalars(select(RefreshTokenRow).where(RefreshTokenRow.tenant_id==target,RefreshTokenRow.user_id!=p.user_id,RefreshTokenRow.revoked.is_(False)))).all()
        for r in rows:r.revoked=True
        _audit(db,target,"admin.sessions.revoked_all",target,{"actor":p.user_id,"count":len(rows)}); return {"revoked":len(rows)}

@router.get("/api-keys")
async def api_keys(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        rows=(await db.scalars(select(ApiKeyRow).where(ApiKeyRow.tenant_id==target).order_by(ApiKeyRow.created_at.desc()))).all()
        return {"keys":[{"key_id":r.key_id,"name":r.name,"user_id":r.user_id,"scopes":r.scopes,"expires_at":r.expires_at.isoformat() if r.expires_at else None,"last_used_at":r.last_used_at.isoformat() if r.last_used_at else None,"revoked":r.revoked,"created_at":r.created_at.isoformat()} for r in rows]}
@router.post("/api-keys")
async def create_api_key(body:ApiKeyCreate,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,body.tenant_id,required_for_owner=p.role=="owner"); raw="sgm_"+secrets.token_urlsafe(32); kid=secrets.token_hex(12); exp=utcnow()+timedelta(days=body.expires_in_days) if body.expires_in_days else None
    scopes=sorted(set(body.scopes or ["scanner:read","scanner:run","reports:read"]))
    invalid_scopes=set(scopes)-ALLOWED_API_KEY_SCOPES
    if invalid_scopes:
        raise HTTPException(422, f"Unsupported API key scopes: {sorted(invalid_scopes)}")
    if "admin:*" in scopes and p.role != "owner":
        raise HTTPException(403, "Only the platform owner can create an admin API key")
    async with session_scope(target) as db:
        key_user_id=p.user_id
        if p.tenant_id != target:
            key_owner=await db.scalar(select(UserRow).where(UserRow.tenant_id==target,UserRow.is_active.is_(True)).order_by(UserRow.role.desc(),UserRow.created_at.asc()).limit(1))
            if not key_owner: raise HTTPException(409,"The target organization has no active user to own the API key")
            key_user_id=key_owner.user_id
        db.add(ApiKeyRow(key_id=kid,tenant_id=target,user_id=key_user_id,name=body.name,key_hash=hashlib.sha256(raw.encode()).hexdigest(),scopes=scopes,expires_at=exp,created_at=utcnow(),revoked=False)); _audit(db,target,"admin.api_key.created",kid,{"actor":p.user_id,"scopes":scopes})
    await record_security_event(tenant_id=target,event_type="admin.api_key.created",actor_user_id=p.user_id,target=kid,data={"scopes":scopes,"name":body.name})
    return {"key_id":kid,"secret":raw,"name":body.name,"scopes":scopes,"expires_at":exp.isoformat() if exp else None,"warning":"Store this secret now. It will never be returned again."}
@router.post("/api-keys/{key_id}/revoke")
async def revoke_api_key(key_id:str,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db:
        r=await db.get(ApiKeyRow,key_id)
        if not r or r.tenant_id!=target: raise HTTPException(404,"API key not found")
        r.revoked=True; _audit(db,target,"admin.api_key.revoked",key_id,{"actor":p.user_id}); return {"ok":True}


@router.get("/security/events")
async def security_events(_:object=Depends(require_admin), limit:int=Query(default=100,ge=1,le=500), severity:str|None=None,tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    from app.core.database import SecurityEventRow
    async with session_scope(target) as db:
        stmt=select(SecurityEventRow).where(SecurityEventRow.tenant_id==target).order_by(SecurityEventRow.created_at.desc()).limit(limit)
        if severity: stmt=stmt.where(SecurityEventRow.severity==severity)
        rows=(await db.scalars(stmt)).all()
    return {"events":[{"event_id":r.event_id,"event_type":r.event_type,"severity":r.severity,"actor_user_id":r.actor_user_id,"target":r.target,"data":r.data,"risk_score":r.risk_score,"detected":r.detected,"created_at":r.created_at.isoformat()} for r in rows]}

@router.get("/security/alerts")
async def security_alerts(_:object=Depends(require_admin), status:str|None=None, limit:int=Query(default=100,ge=1,le=500),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    from app.core.database import SecurityAlertRow
    async with session_scope(target) as db:
        stmt=select(SecurityAlertRow).where(SecurityAlertRow.tenant_id==target).order_by(SecurityAlertRow.created_at.desc()).limit(limit)
        if status: stmt=stmt.where(SecurityAlertRow.status==status)
        rows=(await db.scalars(stmt)).all()
    return {"alerts":[{"alert_id":r.alert_id,"event_id":r.event_id,"title":r.title,"severity":r.severity,"status":r.status,"risk_score":r.risk_score,"data":r.data,"created_at":r.created_at.isoformat(),"acknowledged_at":r.acknowledged_at.isoformat() if r.acknowledged_at else None,"incident_id":r.incident_id} for r in rows]}

class AlertStatusUpdate(BaseModel):
    status:str=Field(pattern="^(open|acknowledged|resolved)$")

@router.patch("/security/alerts/{alert_id}")
async def update_alert(alert_id:str,body:AlertStatusUpdate,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    from app.core.database import SecurityAlertRow
    async with session_scope(target) as db:
        r=await db.get(SecurityAlertRow,alert_id)
        if not r or r.tenant_id!=target: raise HTTPException(404,"Alert not found")
        r.status=body.status; r.acknowledged_at=utcnow() if body.status!="open" else None
        _audit(db,target,"security.alert.updated",alert_id,{"actor":p.user_id,"status":r.status})
        return {"ok":True,"status":r.status}

@router.get("/incidents")
async def incidents(_:object=Depends(require_admin), status:str|None=None, limit:int=Query(default=100,ge=1,le=500),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    from app.core.database import IncidentRow
    async with session_scope(target) as db:
        stmt=select(IncidentRow).where(IncidentRow.tenant_id==target).order_by(IncidentRow.updated_at.desc()).limit(limit)
        if status: stmt=stmt.where(IncidentRow.status==status)
        rows=(await db.scalars(stmt)).all()
    return {"incidents":[{"incident_id":r.incident_id,"title":r.title,"description":r.description,"severity":r.severity,"status":r.status,
        "assignee_user_id":r.assignee_user_id,"sla_due_at":r.sla_due_at.isoformat() if r.sla_due_at else None,
        "related_asset_id":r.related_asset_id,"related_scan_id":r.related_scan_id,"related_finding_id":r.related_finding_id,
        "related_user_id":r.related_user_id,"evidence":r.evidence,"timeline":r.timeline,"ai_explanation":r.ai_explanation,
        "created_at":r.created_at.isoformat(),"updated_at":r.updated_at.isoformat()} for r in rows]}

class IncidentCreate(BaseModel):
    title:str=Field(min_length=3,max_length=240)
    tenant_id:str|None=None
    description:str=""
    severity:str=Field(default="high",pattern="^(low|medium|high|critical)$")
    assignee_user_id:str|None=None
    sla_due_at:str|None=None
    related:dict[str,object]=Field(default_factory=dict)
    evidence:list[dict[str,object]]=Field(default_factory=list)

class IncidentUpdate(BaseModel):
    status:str|None=Field(default=None,pattern="^(open|investigating|resolved|closed)$")
    assignee_user_id:str|None=None
    ai_explanation:str|None=None
    evidence:list[dict[str,object]]|None=None
    note:str|None=None

@router.post("/incidents")
async def create_incident_route(body:IncidentCreate,_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    from app.core.security_events import create_incident
    p=current_principal()
    due=None
    if body.sla_due_at:
        try: due=__import__("datetime").datetime.fromisoformat(body.sla_due_at.replace("Z","+00:00"))
        except ValueError: raise HTTPException(422,"Invalid sla_due_at")
    target=await _target_tenant(p,body.tenant_id,required_for_owner=p.role=="owner")
    iid=await create_incident(tenant_id=target,title=body.title,description=body.description,severity=body.severity,
                        assignee_user_id=body.assignee_user_id,sla_due_at=due,related=body.related,evidence=body.evidence)
    return {"incident_id":iid}

@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id:str,body:IncidentUpdate,tenant_id:str|None=Query(default=None),_:object=Depends(require_admin),step:object=Depends(require_step_up)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    from app.core.database import IncidentRow
    async with session_scope(target) as db:
        r=await db.get(IncidentRow,incident_id)
        if not r or r.tenant_id!=target: raise HTTPException(404,"Incident not found")
        if body.status is not None: r.status=body.status
        if body.assignee_user_id is not None: r.assignee_user_id=body.assignee_user_id
        if body.ai_explanation is not None: r.ai_explanation=body.ai_explanation
        if body.evidence is not None: r.evidence=body.evidence
        timeline=list(r.timeline or []); timeline.append({"at":utcnow().isoformat(),"event":"incident.updated","actor":p.user_id,"note":body.note or ""})
        r.timeline=timeline; r.updated_at=utcnow(); _audit(db,target,"security.incident.updated",incident_id,{"actor":p.user_id,"status":r.status})
        return {"ok":True,"incident_id":incident_id,"status":r.status}

@router.get("/security/summary")
async def security_summary(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    from app.core.database import SecurityAlertRow, IncidentRow, SecurityEventRow
    async with session_scope(target) as db:
        open_alerts=await db.scalar(select(func.count()).select_from(SecurityAlertRow).where(SecurityAlertRow.tenant_id==target,SecurityAlertRow.status=="open")) or 0
        critical=await db.scalar(select(func.count()).select_from(SecurityAlertRow).where(SecurityAlertRow.tenant_id==target,SecurityAlertRow.severity=="critical",SecurityAlertRow.status!="resolved")) or 0
        incidents_open=await db.scalar(select(func.count()).select_from(IncidentRow).where(IncidentRow.tenant_id==target,IncidentRow.status.in_(["open","investigating"]))) or 0
        events_24h=await db.scalar(select(func.count()).select_from(SecurityEventRow).where(SecurityEventRow.tenant_id==target,SecurityEventRow.created_at>=utcnow()-timedelta(hours=24))) or 0
    return {"open_alerts":open_alerts,"critical_alerts":critical,"open_incidents":incidents_open,"events_24h":events_24h}

@router.get("/scan-governance")
async def scan_governance(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    async with session_scope(target) as db: return (await _setting(db,target)).scan_policy

@router.get("/health")
async def admin_health(_:object=Depends(require_admin),tenant_id:str|None=Query(default=None)):
    p=current_principal(); target=await _target_tenant(p,tenant_id,required_for_owner=p.role=="owner")
    checks={}
    try:
        async with session_scope(target) as db: await db.execute(select(func.count()).select_from(UserRow))
        checks["database"]="healthy"
    except Exception: checks["database"]="degraded"
    checks["supabase_auth"]="configured" if settings.SUPABASE_URL else "not_configured"
    checks["gemini"]="configured" if settings.GEMINI_API_KEY else "not_configured"
    checks["redis"]="configured" if settings.REDIS_URL else "not_configured"
    return {"checks":checks,"environment":settings.ENVIRONMENT,"target_scope_enforced":settings.ENFORCE_TARGET_SCOPE}

@router.get("/backup")
async def backup_status(_:object=Depends(require_admin)):
    return {"status":"external-backup-required","note":"Configure Supabase/Postgres managed backups and verify restores outside the application.","application_triggered_backup":False}