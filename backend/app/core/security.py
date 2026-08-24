"""Authentication compatibility layer used by existing routes.

Existing endpoints keep their dependency name so the frontend contract stays stable,
but production authentication is now user Bearer-token based with tenant context.
"""
from fastapi import Header
from app.core.auth import authenticate_request, require_role
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
