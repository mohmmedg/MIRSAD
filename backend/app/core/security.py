"""Authentication compatibility layer used by existing routes.

Existing endpoints keep their dependency name so the frontend contract stays stable,
but production authentication is now user Bearer-token based with tenant context.
"""
from fastapi import Header, HTTPException
from app.core.auth import authenticate_request, require_role, current_principal, current_principal_optional, ROLE_RANK
from app.core.auth_context import tenant_context

async def verify_api_key(authorization: str|None=Header(default=None), x_api_key: str|None=Header(default=None)):
    p=await authenticate_request(authorization,x_api_key); tenant_context.set(p.tenant_id); return p

async def verify_role(required: str, x_api_key: str|None=None, authorization: str|None=None):
    return await require_role(required,authorization,x_api_key)

async def require_viewer():
    return await require_role('viewer')
async def require_analyst():
    return await require_role('analyst')
async def require_admin():
    return await require_role('admin')


_SCOPE_ROLE_FALLBACK = {"scanner:run": "analyst", "scanner:pause": "analyst", "scanner:cancel": "analyst", "reports:read": "viewer", "scanner:read": "viewer", "finding:lifecycle": "analyst", "admin:*": "admin"}

async def require_scope(scope: str):
    p = current_principal_optional() or await authenticate_request(None, None)
    if p.auth_provider == "api_key":
        if "admin:*" not in p.scopes and scope not in p.scopes:
            raise HTTPException(status_code=403, detail=f"Missing API key scope: {scope}")
    else:
        role = _SCOPE_ROLE_FALLBACK.get(scope, "admin")
        if ROLE_RANK.get(p.role, 0) < ROLE_RANK.get(role, 999):
            raise HTTPException(status_code=403, detail="Insufficient role")
    return p

async def require_scan_execution():
    p = await require_role("analyst")
    if p.auth_provider == "api_key" and "admin:*" not in p.scopes and "scanner:run" not in p.scopes:
        raise HTTPException(status_code=403, detail="Missing API key scope: scanner:run")
    return p


async def require_scanner_run(): return await require_scope("scanner:run")
async def require_scanner_pause(): return await require_scope("scanner:pause")
async def require_scanner_cancel(): return await require_scope("scanner:cancel")
async def require_finding_lifecycle(): return await require_scope("finding:lifecycle")
async def require_reports_read(): return await require_scope("reports:read")
