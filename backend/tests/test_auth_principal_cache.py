import time

import jwt

from app.core import auth
from app.core.config import settings


def _token(exp_in: int) -> str:
    return jwt.encode({"sub": "u1", "exp": int(time.time()) + exp_in}, "k", algorithm="HS256")


def test_cache_hit_expiry_and_invalidation(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_PRINCIPAL_CACHE_SECONDS", 20, raising=False)
    auth.invalidate_principal_cache()
    p = auth.Principal("u1", "t1", "viewer", "a@b.c")
    tok = _token(3600)
    assert auth._principal_cache_get(tok) is None
    auth._principal_cache_put(tok, p)
    assert auth._principal_cache_get(tok) is p
    auth.invalidate_principal_cache()
    assert auth._principal_cache_get(tok) is None


def test_cache_never_outlives_token_and_can_be_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_PRINCIPAL_CACHE_SECONDS", 20, raising=False)
    auth.invalidate_principal_cache()
    p = auth.Principal("u1", "t1", "viewer", "a@b.c")
    expired = _token(-5)
    auth._principal_cache_put(expired, p)
    assert auth._principal_cache_get(expired) is None
    monkeypatch.setattr(settings, "AUTH_PRINCIPAL_CACHE_SECONDS", 0, raising=False)
    tok = _token(3600)
    auth._principal_cache_put(tok, p)
    assert auth._principal_cache_get(tok) is None


def test_raw_token_is_not_stored(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_PRINCIPAL_CACHE_SECONDS", 20, raising=False)
    auth.invalidate_principal_cache()
    tok = _token(3600)
    auth._principal_cache_put(tok, auth.Principal("u1", "t1", "viewer", "a@b.c"))
    assert tok not in auth._PRINCIPAL_CACHE
