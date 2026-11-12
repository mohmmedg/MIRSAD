import time
import uuid
import jwt

from app.core import auth
from app.core.config import settings
from app.core.database import init_db


async def test_supabase_hs256_token_maps_tenant_and_role(monkeypatch):
    init_db()
    secret = "unit-supabase-secret-32-bytes-long-xxxxxxxx"
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://unit.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", secret)
    monkeypatch.setattr(settings, "SUPABASE_JWT_ISSUER", "https://unit.supabase.co/auth/v1")
    monkeypatch.setattr(settings, "SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(settings, "SUPABASE_TENANT_CLAIM", "tenant_id")
    monkeypatch.setattr(settings, "SUPABASE_ROLE_CLAIM", "app_metadata.role")
    monkeypatch.setattr(settings, "SUPABASE_AUTO_PROVISION", True)

    uid = str(uuid.uuid4())
    now = int(time.time())
    token = jwt.encode(
        {"sub": uid, "email": f"{uid}@example.test", "aud": "authenticated", "iss": "https://unit.supabase.co/auth/v1",
         "iat": now, "exp": now + 600, "tenant_id": "tenant-test", "app_metadata": {"role": "analyst"}},
        secret, algorithm="HS256",
    )
    principal = await auth._authenticate_supabase(token)
    assert principal.user_id == uid
    assert principal.tenant_id == "tenant-test"
    assert principal.role == "analyst"


async def test_supabase_signup_joins_named_existing_tenant_as_viewer(monkeypatch):
    init_db()
    secret = "unit-supabase-secret-32-bytes-long-xxxxxxxx"
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://unit.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", secret)
    monkeypatch.setattr(settings, "SUPABASE_JWT_ISSUER", "https://unit.supabase.co/auth/v1")
    monkeypatch.setattr(settings, "SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(settings, "SUPABASE_TENANT_CLAIM", "app_metadata.tenant_id")
    monkeypatch.setattr(settings, "SUPABASE_ROLE_CLAIM", "app_metadata.role")
    monkeypatch.setattr(settings, "SUPABASE_AUTO_PROVISION", True)
    monkeypatch.setattr(settings, "SUPABASE_ALLOW_SELF_SERVICE_SIGNUP", True)
    monkeypatch.setattr(settings, "SUPABASE_ALLOW_JOIN_TENANT_BY_NAME", True)  # explicit opt-in (default is off)

    from app.core.database import TenantRow, UserRow, session_scope, utcnow

    tenant_id = "tenant-existing-" + uuid.uuid4().hex[:8]
    uid = str(uuid.uuid4())
    org_name = "Acme Security " + uuid.uuid4().hex[:6]

    async with session_scope() as db:
        db.add(TenantRow(tenant_id=tenant_id, name=org_name, created_at=utcnow()))

    now = int(time.time())
    token = jwt.encode(
        {
            "sub": uid,
            "email": f"{uid}@example.test",
            "aud": "authenticated",
            "iss": "https://unit.supabase.co/auth/v1",
            "iat": now,
            "exp": now + 600,
            "user_metadata": {"tenant_name": f"  {org_name}  "},
            # Even if an untrusted signup payload contains a role-like value,
            # joining an existing organization must remain viewer-only.
            "app_metadata": {"role": "admin"},
        },
        secret,
        algorithm="HS256",
    )

    principal = await auth._authenticate_supabase(token)

    assert principal.user_id == uid
    assert principal.tenant_id == tenant_id
    assert principal.role == "viewer"

    async with session_scope(tenant_id) as db:
        user = await db.get(UserRow, uid)
        assert user is not None
        assert user.tenant_id == tenant_id
        assert user.role == "viewer"


async def test_supabase_signup_with_ambiguous_tenant_name_is_rejected(monkeypatch):
    init_db()
    secret = "unit-supabase-secret-32-bytes-long-xxxxxxxx"
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://unit.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", secret)
    monkeypatch.setattr(settings, "SUPABASE_JWT_ISSUER", "https://unit.supabase.co/auth/v1")
    monkeypatch.setattr(settings, "SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(settings, "SUPABASE_TENANT_CLAIM", "app_metadata.tenant_id")
    monkeypatch.setattr(settings, "SUPABASE_ROLE_CLAIM", "app_metadata.role")
    monkeypatch.setattr(settings, "SUPABASE_AUTO_PROVISION", True)
    monkeypatch.setattr(settings, "SUPABASE_ALLOW_SELF_SERVICE_SIGNUP", True)
    monkeypatch.setattr(settings, "SUPABASE_ALLOW_JOIN_TENANT_BY_NAME", True)  # explicit opt-in (default is off)

    from app.core.database import TenantRow, session_scope, utcnow
    from fastapi import HTTPException

    org_name = "Duplicate Org " + uuid.uuid4().hex[:6]
    async with session_scope() as db:
        db.add(TenantRow(tenant_id="tenant-a-" + uuid.uuid4().hex[:8], name=org_name, created_at=utcnow()))
        db.add(TenantRow(tenant_id="tenant-b-" + uuid.uuid4().hex[:8], name=org_name, created_at=utcnow()))

    uid = str(uuid.uuid4())
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": uid,
            "email": f"{uid}@example.test",
            "aud": "authenticated",
            "iss": "https://unit.supabase.co/auth/v1",
            "iat": now,
            "exp": now + 600,
            "user_metadata": {"tenant_name": org_name},
        },
        secret,
        algorithm="HS256",
    )

    try:
        await auth._authenticate_supabase(token)
        raise AssertionError("Expected ambiguous organization name to be rejected")
    except HTTPException as exc:
        assert exc.status_code == 409


async def test_join_existing_tenant_by_name_is_disabled_by_default(monkeypatch):
    """user_metadata.tenant_name is user-controlled: it must NOT place a user inside an existing tenant by default."""
    init_db()
    secret = "unit-supabase-secret-32-bytes-long-xxxxxxxx"
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://unit.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", secret)
    monkeypatch.setattr(settings, "SUPABASE_JWT_ISSUER", "https://unit.supabase.co/auth/v1")
    monkeypatch.setattr(settings, "SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(settings, "SUPABASE_TENANT_CLAIM", "app_metadata.tenant_id")
    monkeypatch.setattr(settings, "SUPABASE_ROLE_CLAIM", "app_metadata.role")
    monkeypatch.setattr(settings, "SUPABASE_AUTO_PROVISION", True)
    monkeypatch.setattr(settings, "SUPABASE_ALLOW_SELF_SERVICE_SIGNUP", True)
    monkeypatch.setattr(settings, "SUPABASE_ALLOW_JOIN_TENANT_BY_NAME", False)

    from app.core.auth import _authenticate_supabase
    from app.core.database import TenantRow, session_scope, utcnow

    victim_tenant = "tenant-victim-" + uuid.uuid4().hex[:8]
    org_name = "Victim Org " + uuid.uuid4().hex[:6]
    async with session_scope() as db:
        db.add(TenantRow(tenant_id=victim_tenant, name=org_name, created_at=utcnow()))

    uid = str(uuid.uuid4())
    now = int(time.time())
    token = jwt.encode(
        {"sub": uid, "email": f"{uid}@example.test", "aud": "authenticated",
         "iss": "https://unit.supabase.co/auth/v1", "iat": now, "exp": now + 3600,
         "user_metadata": {"tenant_name": org_name}},
        secret, algorithm="HS256",
    )
    try:
        principal = await _authenticate_supabase(token)
    except Exception:
        return  # rejected outright is also acceptable
    assert principal.tenant_id != victim_tenant
