import time
import uuid
import jwt

from app.core import auth
from app.core.config import settings
from app.core.database import init_db


def test_supabase_hs256_token_maps_tenant_and_role(monkeypatch):
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
    principal = auth._authenticate_supabase(token)
    assert principal.user_id == uid
    assert principal.tenant_id == "tenant-test"
    assert principal.role == "analyst"
