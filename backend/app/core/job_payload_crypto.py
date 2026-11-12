"""Encrypt credential-bearing fields in durable scan job payloads.

Scan jobs are durable because workers may run in a different container/process.
That means credentials cannot simply stay in request memory.  This module keeps
those fields out of plaintext PostgreSQL JSON while still making them available
to the worker that owns the job.

The key is read from JOB_PAYLOAD_ENCRYPTION_KEY.  For backwards-compatible local
stacks, REDIS_PASSWORD or SUPABASE_JWT_SECRET is used as key material when the
explicit key is absent.  Operators should set JOB_PAYLOAD_ENCRYPTION_KEY to a
stable, dedicated secret in production.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

SENSITIVE_JOB_FIELDS = frozenset({
    "login_username",
    "login_password",
    "auth_header",
    "cookie",
    "authorized_auth_header",
    "authorized_cookie",
    "unauthorized_auth_header",
    "unauthorized_cookie",
})
_ENCRYPTED_FIELD = "_encrypted_secrets"


def _fernet() -> Fernet:
    material = (
        getattr(settings, "JOB_PAYLOAD_ENCRYPTION_KEY", None)
        or getattr(settings, "SUPABASE_JWT_SECRET", None)
        or getattr(settings, "REDIS_PASSWORD", None)
    )
    if not material:
        raise RuntimeError(
            "JOB_PAYLOAD_ENCRYPTION_KEY is required when a scan includes credentials "
            "or authentication headers/cookies."
        )
    key = base64.urlsafe_b64encode(hashlib.sha256(str(material).encode("utf-8")).digest())
    return Fernet(key)


def protect_job_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Return a DB-safe payload with sensitive fields encrypted and removed."""
    out = dict(payload or {})
    secrets = {key: out.pop(key) for key in SENSITIVE_JOB_FIELDS if key in out and out[key] is not None}
    if secrets:
        token = _fernet().encrypt(json.dumps(secrets, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        out[_ENCRYPTED_FIELD] = token.decode("ascii")
    return out


def restore_job_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Restore encrypted credentials for the worker without mutating the stored payload."""
    out = dict(payload or {})
    token = out.pop(_ENCRYPTED_FIELD, None)
    if not token:
        return out
    try:
        restored = json.loads(_fernet().decrypt(str(token).encode("ascii")).decode("utf-8"))
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Unable to decrypt the credentials for this scan job") from exc
    if not isinstance(restored, dict):
        raise RuntimeError("Encrypted scan credentials have an invalid format")
    out.update(restored)
    return out
