"""SF-01 regression tests.

Before this fix, `session_timeout_minutes`, `max_concurrent_sessions` and
`force_logout_on_role_change` were defined in the tenant security policy and
shown in the admin panel, but `authenticate_request()` never called any of
the enforcement helpers that implement them — so none of the three controls
had any real effect on an actual request. These tests exercise the real
entry point, `auth._authenticate_supabase()`, end to end with a real signed
JWT, not the enforcement helpers in isolation.
"""
import time
import uuid

import jwt
import pytest
from fastapi import HTTPException

from app.core import auth
from app.core.config import settings
from app.core.database import AdminSettingRow, UserRow, session_scope, utcnow, init_db


async def _set_security_policy(tenant_id: str, **overrides):
    async with session_scope(tenant_id) as db:
        row = await db.get(AdminSettingRow, tenant_id)
        if row is None:
            row = AdminSettingRow(
                tenant_id=tenant_id,
                security_policy={},
                scan_policy={},
                ai_policy={},
                notification_policy={},
                updated_at=utcnow(),
            )
            db.add(row)
        row.security_policy = {**(row.security_policy or {}), **overrides}


SECRET = "unit-supabase-secret-32-bytes-long-xxxxxxxx"


def _configure_supabase(monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://unit.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", SECRET)
    monkeypatch.setattr(settings, "SUPABASE_JWT_ISSUER", "https://unit.supabase.co/auth/v1")
    monkeypatch.setattr(settings, "SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(settings, "SUPABASE_TENANT_CLAIM", "tenant_id")
    monkeypatch.setattr(settings, "SUPABASE_ROLE_CLAIM", "app_metadata.role")
    monkeypatch.setattr(settings, "SUPABASE_AUTO_PROVISION", True)


def _token(uid: str, tenant_id: str, iat: int, session_id: str | None = None, role: str = "analyst"):
    claims = {
        "sub": uid,
        "email": f"{uid}@example.test",
        "aud": "authenticated",
        "iss": "https://unit.supabase.co/auth/v1",
        "iat": iat,
        "exp": iat + 3600,
        "tenant_id": tenant_id,
        "app_metadata": {"role": role},
    }
    if session_id:
        claims["session_id"] = session_id
    return jwt.encode(claims, SECRET, algorithm="HS256")


async def _provision(monkeypatch) -> tuple[str, str]:
    """First-ever login for a fresh user provisions it; returns (uid, tenant_id)."""
    init_db()
    _configure_supabase(monkeypatch)
    uid = str(uuid.uuid4())
    tenant_id = f"tenant-sf01-{uid[:8]}"
    now = int(time.time())
    principal = await auth._authenticate_supabase(_token(uid, tenant_id, now))
    assert principal.user_id == uid
    return uid, tenant_id


async def test_session_timeout_minutes_is_enforced(monkeypatch):
    uid, tenant_id = await _provision(monkeypatch)
    await _set_security_policy(tenant_id, session_timeout_minutes=1)

    stale_token = _token(uid, tenant_id, int(time.time()) - 120)  # 2 minutes old, limit is 1
    with pytest.raises(HTTPException) as exc:
        await auth._authenticate_supabase(stale_token)
    assert exc.value.status_code == 401

    fresh_token = _token(uid, tenant_id, int(time.time()))
    principal = await auth._authenticate_supabase(fresh_token)
    assert principal.user_id == uid


async def test_force_logout_on_role_change_rejects_pre_change_token(monkeypatch):
    uid, tenant_id = await _provision(monkeypatch)

    old_token = _token(uid, tenant_id, int(time.time()))
    time.sleep(1.1)

    async with session_scope(tenant_id) as db:
        user = await db.get(UserRow, uid)
        user.role = "admin"
        user.security_changed_at = utcnow()

    # A token issued before the security-relevant change must be rejected...
    with pytest.raises(HTTPException) as exc:
        await auth._authenticate_supabase(old_token)
    assert exc.value.status_code == 401

    # ...but a token issued after it is accepted.
    new_token = _token(uid, tenant_id, int(time.time()) + 1)
    principal = await auth._authenticate_supabase(new_token)
    assert principal.user_id == uid


async def test_max_concurrent_sessions_fails_open_without_auth_schema(monkeypatch):
    """The unit-test DB is SQLite with no `auth` schema at all. The check
    must fail open (never raise) rather than lock every tenant out because
    of a missing/inaccessible auth.sessions table."""
    uid, tenant_id = await _provision(monkeypatch)
    await _set_security_policy(tenant_id, max_concurrent_sessions=1)

    token = _token(uid, tenant_id, int(time.time()), session_id=str(uuid.uuid4()))
    principal = await auth._authenticate_supabase(token)  # must not raise
    assert principal.user_id == uid
