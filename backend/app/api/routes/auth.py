from __future__ import annotations
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from app.core.config import settings
from app.core.auth import authenticate_request
from app.core.database import TenantRow, session_scope

router = APIRouter(prefix='/auth', tags=['authentication'])

# مصادقة محلية (local password/JWT) أُزيلت بالكامل من هذا المشروع.
# المصادقة الآن تمر حصراً عبر Supabase Auth مباشرة من الواجهة
# (frontend/src/auth/supabase.ts)، والـ backend لا يفعل شيئاً أكثر من التحقق
# من توكن Supabase الوارد (انظر app.core.auth._authenticate_supabase) وربطه
# بمستخدم/tenant مُزوَّد تلقائياً (SUPABASE_AUTO_PROVISION). لذلك لا توجد
# هنا أي نقاط /register أو /login أو /refresh أو /logout — تلك تخص Supabase
# نفسه (GoTrue)، وليست من مسؤولية هذا الـ backend.


class AuthMeResponse(BaseModel):
    user_id: str
    tenant_id: str
    tenant_name: str
    email: str
    role: str
    aal: str
    amr: list[str]
    auth_provider: str
    mfa_required: bool


@router.get('/me', response_model=AuthMeResponse)
async def auth_me(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
):
    """Return the server-authoritative identity and current MFA state.

    This endpoint deliberately does not require admin/AAL2 itself. An admin
    who has just completed password authentication must be able to reach the
    MFA screen and obtain the second factor before privileged endpoints are
    unlocked. The privileged routes remain protected by require_admin().
    """
    principal = await authenticate_request(authorization, x_api_key)
    mfa_required = (
        principal.auth_provider == 'supabase'
        and principal.role in {'admin', 'owner'}
        and principal.aal != 'aal2'
    )
    async with session_scope(principal.tenant_id) as db:
        tenant = await db.get(TenantRow, principal.tenant_id)
    tenant_name = (tenant.name if tenant else None) or principal.tenant_id

    return AuthMeResponse(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        tenant_name=tenant_name,
        email=principal.email,
        role=principal.role,
        aal=principal.aal,
        amr=principal.amr,
        auth_provider=principal.auth_provider,
        mfa_required=mfa_required,
    )


class SetupStatusResponse(BaseModel):
    self_service_signup_enabled: bool


@router.get('/setup-status', response_model=SetupStatusResponse)
async def setup_status():
    """Public, unauthenticated, and intentionally low-information: tells the
    frontend whether to show a registration form or a 'contact your
    administrator' message. Never reveals emails, user counts, or tenant
    names. Governed purely by SUPABASE_ALLOW_SELF_SERVICE_SIGNUP — the same
    rule for every visitor regardless of whether the database happens to be
    empty."""
    return SetupStatusResponse(
        self_service_signup_enabled=bool(settings.SUPABASE_ALLOW_SELF_SERVICE_SIGNUP)
    )
