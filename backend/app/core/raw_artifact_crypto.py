from __future__ import annotations
import base64, hashlib
from cryptography.fernet import Fernet
from app.core.config import settings

def _fernet() -> Fernet:
    material = (
        getattr(settings, "JOB_PAYLOAD_ENCRYPTION_KEY", None)
        or getattr(settings, "SUPABASE_JWT_SECRET", None)
        or getattr(settings, "API_KEY", None)
    )
    if not material:
        # Fail closed, same as job_payload_crypto._fernet(): a static
        # hardcoded fallback here would mean raw scan artifacts (which can
        # contain credentials/auth headers captured from the target) are
        # only "encrypted" with a key visible in the source code, i.e. not
        # encrypted at all against anyone who can read this repo.
        raise RuntimeError(
            "JOB_PAYLOAD_ENCRYPTION_KEY (or SUPABASE_JWT_SECRET / API_KEY as a "
            "fallback) must be set before raw artifacts can be encrypted or "
            "decrypted. Refusing to fall back to a hardcoded key."
        )
    key = base64.urlsafe_b64encode(hashlib.sha256(str(material).encode("utf-8")).digest())
    return Fernet(key)

def encrypt_artifact(data: bytes) -> bytes:
    return _fernet().encrypt(data)

def decrypt_artifact(data: bytes) -> bytes:
    return _fernet().decrypt(data)
