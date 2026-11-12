"""Minimal self-hosted OOB callback correlation for authorized assessments.

The callback endpoint stores only a random correlation token and timestamps.
No request body, cookies, authorization headers, or target payloads are persisted.
Redis is preferred in production; an in-process fallback is provided for local E2E.
"""
from __future__ import annotations
import time
from typing import Any
from app.core.config import settings

_MEM: dict[str, tuple[float, bool]] = {}
PREFIX = "mirsad:oob:"

def _redis():
    try:
        from app.core.redis_queue import client
        return client()
    except Exception:
        return None

def issue_token(ttl: int | None = None) -> str:
    import secrets
    token = secrets.token_urlsafe(24)
    expires = time.time() + int(ttl or settings.OOB_CALLBACK_TOKEN_TTL_SECONDS)
    r = _redis()
    if r:
        r.setex(PREFIX + token, int(max(1, expires-time.time())), "0")
    else:
        _MEM[token] = (expires, False)
    return token

def mark(token: str) -> bool:
    now = time.time()
    r = _redis()
    if r:
        key = PREFIX + token
        if not r.exists(key):
            return False
        r.setex(key, int(max(1, settings.OOB_CALLBACK_TOKEN_TTL_SECONDS)), "1")
        return True
    item = _MEM.get(token)
    if not item or item[0] < now:
        _MEM.pop(token, None)
        return False
    _MEM[token] = (now + int(settings.OOB_CALLBACK_TOKEN_TTL_SECONDS), True)
    return True

def observed(token: str) -> bool:
    r = _redis()
    if r:
        return r.get(PREFIX + token) == "1"
    item = _MEM.get(token)
    return bool(item and item[0] > time.time() and item[1])
