from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel
from app.core.config import settings

router = APIRouter(prefix='/auth', tags=['authentication'])

# مصادقة محلية (local password/JWT) أُزيلت بالكامل من هذا المشروع.
# المصادقة الآن تمر حصراً عبر Supabase Auth مباشرة من الواجهة
# (frontend/src/auth/supabase.ts)، والـ backend لا يفعل شيئاً أكثر من التحقق
# من توكن Supabase الوارد (انظر app.core.auth._authenticate_supabase) وربطه
# بمستخدم/tenant مُزوَّد تلقائياً (SUPABASE_AUTO_PROVISION). لذلك لا توجد
# هنا أي نقاط /register أو /login أو /refresh أو /logout — تلك تخص Supabase
# نفسه (GoTrue)، وليست من مسؤولية هذا الـ backend.


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
