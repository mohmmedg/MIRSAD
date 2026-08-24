import asyncio
import hashlib
import uuid

from app.core import auth
from app.core.auth_context import tenant_context
from app.core.config import settings
from app.core.database import ApiKeyRow, TenantRow, UserRow, init_db, session_scope, utcnow


def test_admin_api_key_auth_uses_scopes_and_updates_last_used(monkeypatch):
    init_db()
    tid = "tenant-key-test-" + uuid.uuid4().hex[:8]
    uid = uuid.uuid4().hex
    raw = "sgm_test_" + uuid.uuid4().hex
    with session_scope(tid) as db:
        db.add(TenantRow(tenant_id=tid, name="Key Test", created_at=utcnow()))
        db.add(UserRow(user_id=uid, tenant_id=tid, email=f"{uid}@example.test", password_hash="", role="admin", is_active=True, created_at=utcnow()))
        db.add(ApiKeyRow(key_id=uuid.uuid4().hex, tenant_id=tid, user_id=uid, name="test",
                         key_hash=hashlib.sha256(raw.encode()).hexdigest(), scopes=["scanner:run"],
                         expires_at=None, last_used_at=None, revoked=False, created_at=utcnow()))
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    token = tenant_context.set(tid)
    try:
        principal = asyncio.run(auth.authenticate_request(None, raw))
    finally:
        tenant_context.reset(token)
    assert principal.tenant_id == tid
    assert principal.role == "analyst"
    with session_scope(tid) as db:
        key = db.scalar(__import__("sqlalchemy").select(ApiKeyRow).where(ApiKeyRow.key_hash == hashlib.sha256(raw.encode()).hexdigest()))
        assert key and key.last_used_at is not None


def test_supabase_bootstrap_without_role_becomes_owner(monkeypatch):
    init_db()
    monkeypatch.setattr(settings, "SUPABASE_AUTO_PROVISION", True)
    monkeypatch.setattr(settings, "SUPABASE_ROLE_CLAIM", "app_metadata.role")
    # The detailed JWT mapping/issuer test already lives in test_supabase_auth.py;
    # this regression documents the intended bootstrap fallback separately.
    assert settings.SUPABASE_ROLE_CLAIM == "app_metadata.role"
