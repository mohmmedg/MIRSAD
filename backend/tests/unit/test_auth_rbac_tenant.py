"""
tests/unit/test_auth_rbac_tenant.py

ملاحظة: كان هذا الملف يستورد hash_password/verify_password من
app.core.auth، لكن هاتين الدالتين لم تعودا موجودتين إطلاقاً — المصادقة
انتقلت بالكامل إلى التحقق من JWT عبر Supabase (راجع
_authenticate_supabase بملف app/core/auth.py)، وحُذفت آلية كلمة المرور
المحلية القديمة دون تحديث هذا الملف، فكان يفشل حتى بمرحلة التحميل
(import) ويوقف تشغيل كامل حزمة pytest. أُبقي فقط على الاختبار الذي لا
يزال منطقه صحيحاً (ترتيب الأدوار)، وحُذف ما يخص كلمة المرور لأن
الميزة نفسها لم تعد موجودة بالكود.
"""
import os
os.environ.setdefault('AUTH_JWT_SECRET', 'unit-test-secret-that-is-long-enough-32')
from app.core.auth import ROLE_RANK


def test_rbac_order():
    assert ROLE_RANK['viewer'] < ROLE_RANK['analyst'] < ROLE_RANK['admin']
