from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
import threading
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select

from app.core.auth_context import tenant_context
from app.core.config import settings
from app.core.database import AdminSettingRow, JobRow, SecurityEventRow, RefreshTokenRow, session_scope, utcnow

DEFAULT_SECURITY = {
    "allow_registration": False,
    "require_email_verification": True,
    "require_mfa": True,
    "session_timeout_minutes": 60,
    "max_concurrent_sessions": 10,
    "max_failed_logins": 5,
    "force_logout_on_role_change": True,
}
DEFAULT_SCAN = {
    "max_concurrent_scans": 2,
    "max_scan_duration_minutes": 30,
    "max_assets": 1000,
    "max_endpoints": 10000,
    "rate_limit_per_minute": 10,
    "enforce_target_scope": True,
}
DEFAULT_AI = {
    "enabled": True,
    "model": None,
    "timeout_seconds": 30,
    "max_output_tokens": 8192,
    "redact_secrets": True,
    "daily_budget_usd": 0,
    "rate_limit_per_minute": 10,
    "max_input_chars": 200000,
    "max_concurrent_requests": 2,
}

# Conservative hard ceilings. Admin policy can tighten these values but cannot
# turn a security control into an unbounded resource sink.
HARD_MAX_SCAN_DURATION_MINUTES = 120
HARD_MAX_OUTPUT_TOKENS = 16384
HARD_MAX_AI_INPUT_CHARS = 500000
HARD_MAX_AI_CONCURRENCY = 32


def _policy(tenant_id: str) -> AdminSettingRow:
    with session_scope(tenant_id) as db:
        row = db.get(AdminSettingRow, tenant_id)
        if not row:
            row = AdminSettingRow(
                tenant_id=tenant_id,
                security_policy=DEFAULT_SECURITY.copy(),
                scan_policy=DEFAULT_SCAN.copy(),
                ai_policy=DEFAULT_AI.copy(),
                notification_policy={},
                updated_at=utcnow(),
            )
            db.add(row)
            db.flush()
        return row


def get_policies(tenant_id: str | None = None) -> dict[str, dict[str, Any]]:
    tid = tenant_id or tenant_context.get()
    if not tid:
        return {"security": DEFAULT_SECURITY.copy(), "scan": DEFAULT_SCAN.copy(), "ai": DEFAULT_AI.copy()}
    with session_scope(tid) as db:
        row = db.get(AdminSettingRow, tid)
        if not row:
            return {"security": DEFAULT_SECURITY.copy(), "scan": DEFAULT_SCAN.copy(), "ai": DEFAULT_AI.copy()}
        return {
            "security": {**DEFAULT_SECURITY, **(row.security_policy or {})},
            "scan": {**DEFAULT_SCAN, **(row.scan_policy or {})},
            "ai": {**DEFAULT_AI, **(row.ai_policy or {})},
        }


def security_policy(tenant_id: str | None = None) -> dict[str, Any]:
    return get_policies(tenant_id)["security"]


def scan_policy(tenant_id: str | None = None) -> dict[str, Any]:
    return get_policies(tenant_id)["scan"]


def ai_policy(tenant_id: str | None = None) -> dict[str, Any]:
    return get_policies(tenant_id)["ai"]


def validate_policy(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    if kind == "security":
        ints = {"session_timeout_minutes": (1, 1440), "max_concurrent_sessions": (1, 100), "max_failed_logins": (1, 20)}
        bools = {"allow_registration", "require_email_verification", "require_mfa", "force_logout_on_role_change"}
    elif kind == "scan":
        ints = {
            "max_concurrent_scans": (1, 100),
            "max_scan_duration_minutes": (1, HARD_MAX_SCAN_DURATION_MINUTES),
            "max_assets": (1, 100000),
            "max_endpoints": (1, 100000),
            "rate_limit_per_minute": (1, 600),
        }
        bools = {"enforce_target_scope"}
    elif kind == "ai":
        ints = {
            "timeout_seconds": (1, 300),
            "max_output_tokens": (1, HARD_MAX_OUTPUT_TOKENS),
            "rate_limit_per_minute": (1, 120),
            "max_input_chars": (1000, HARD_MAX_AI_INPUT_CHARS),
            "max_concurrent_requests": (1, HARD_MAX_AI_CONCURRENCY),
        }
        bools = {"enabled", "redact_secrets"}
        if "daily_budget_usd" in values:
            try:
                budget = float(values["daily_budget_usd"])
            except (TypeError, ValueError):
                raise HTTPException(422, "daily_budget_usd must be a non-negative number")
            if budget < 0 or budget > 100000:
                raise HTTPException(422, "daily_budget_usd is outside the allowed range")
    else:
        return values
    for key, value in values.items():
        if key in ints:
            if isinstance(value, bool) or not isinstance(value, int) or not (ints[key][0] <= value <= ints[key][1]):
                raise HTTPException(422, f"Invalid {key}: expected integer in {ints[key]}")
        elif key in bools and not isinstance(value, bool):
            raise HTTPException(422, f"Invalid {key}: expected boolean")
        elif key not in ints and key not in bools and key != "daily_budget_usd":
            raise HTTPException(422, f"Unknown policy key: {key}")
    return values


class _RedisCounter:
    def __init__(self) -> None:
        self.redis = None
        if settings.REDIS_URL:
            try:
                import redis
                self.redis = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
            except Exception:
                self.redis = None
        self.local: dict[str, tuple[int, float]] = {}
        self.lock = threading.Lock()

    async def increment(self, key: str, limit: int, ttl: int = 70) -> bool:
        if self.redis is not None:
            try:
                count = int(self.redis.incr(key))
                if count == 1:
                    self.redis.expire(key, ttl)
                if count <= limit:
                    return True
                self.redis.decr(key)
                return False
            except Exception:
                pass
        with self.lock:
            now = time.monotonic()
            current, expires = self.local.get(key, (0, now + ttl))
            if now >= expires:
                current, expires = 0, now + ttl
            if current >= limit:
                self.local[key] = (current, expires)
                return False
            self.local[key] = (current + 1, expires)
            return True

    async def decrement(self, key: str) -> None:
        if self.redis is not None:
            try:
                self.redis.decr(key)
                return
            except Exception:
                pass
        with self.lock:
            current, expires = self.local.get(key, (0, time.monotonic()))
            self.local[key] = (max(0, current - 1), expires)


_COUNTER = _RedisCounter()


async def enforce_policy_rate_limit(kind: str, tenant_id: str, limit: int) -> None:
    bucket = int(time.time() // 60)
    digest = hashlib.sha256(tenant_id.encode()).hexdigest()[:20]
    key = f"security-scanner:policy-rate:{kind}:{digest}:{bucket}"
    if not await _COUNTER.increment(key, max(1, limit), ttl=120):
        raise HTTPException(status_code=429, detail=f"{kind} policy rate limit exceeded")


@asynccontextmanager
async def scan_slot(tenant_id: str):
    policy = scan_policy(tenant_id)
    limit = int(policy["max_concurrent_scans"])
    digest = hashlib.sha256(tenant_id.encode()).hexdigest()[:20]
    key = f"security-scanner:scan-slots:{digest}"
    acquired = await _COUNTER.increment(key, limit, ttl=max(120, int(policy["max_scan_duration_minutes"]) * 60 + 120))
    if not acquired:
        raise HTTPException(status_code=429, detail="Maximum concurrent scans reached for this tenant")
    try:
        yield
    finally:
        await _COUNTER.decrement(key)


async def enforce_ai_request(tenant_id: str, estimated_input_chars: int, estimated_output_tokens: int) -> dict[str, Any]:
    policy = ai_policy(tenant_id)
    if not bool(policy["enabled"]):
        raise HTTPException(status_code=403, detail="AI analysis is disabled by the tenant security policy")
    if estimated_input_chars > int(policy["max_input_chars"]):
        raise HTTPException(status_code=413, detail="AI analysis input exceeds the tenant policy limit")
    await enforce_policy_rate_limit("ai", tenant_id, int(policy["rate_limit_per_minute"]))
    concurrency_key = f"security-scanner:ai-slots:{hashlib.sha256(tenant_id.encode()).hexdigest()[:20]}"
    if not await _COUNTER.increment(concurrency_key, int(policy["max_concurrent_requests"]), ttl=max(120, int(policy["timeout_seconds"]) + 60)):
        raise HTTPException(status_code=429, detail="Maximum concurrent AI requests reached for this tenant")

    try:
        budget = float(policy.get("daily_budget_usd") or 0)
        if budget > 0:
            in_price = float(settings.AI_INPUT_COST_PER_1M_USD)
            out_price = float(settings.AI_OUTPUT_COST_PER_1M_USD)
            if in_price <= 0 or out_price <= 0:
                raise HTTPException(status_code=503, detail="AI daily budget is enabled but provider pricing is not configured")
            estimated_cost = (estimated_input_chars / 4 / 1_000_000) * in_price + (estimated_output_tokens / 1_000_000) * out_price
            since = utcnow() - timedelta(hours=24)
            with session_scope(tenant_id) as db:
                spent = db.scalar(
                    select(func.coalesce(func.sum(SecurityEventRow.data["estimated_cost_usd"].as_float()), 0.0)).where(
                        SecurityEventRow.tenant_id == tenant_id,
                        SecurityEventRow.event_type == "ai.budget_reserved",
                        SecurityEventRow.created_at >= since,
                    )
                ) or 0.0
            if float(spent) + estimated_cost > budget:
                raise HTTPException(status_code=429, detail="AI daily budget exhausted for this tenant")
            with session_scope(tenant_id) as db:
                db.add(SecurityEventRow(
                    event_id="sev_" + uuid.uuid4().hex,
                    tenant_id=tenant_id,
                    event_type="ai.budget_reserved",
                    severity="low",
                    actor_user_id=None,
                    target=None,
                    data={"estimated_cost_usd": estimated_cost, "input_chars": estimated_input_chars, "output_tokens": estimated_output_tokens},
                    risk_score=0,
                    detected=False,
                    created_at=utcnow(),
                ))
        return policy
    except Exception:
        await _COUNTER.decrement(concurrency_key)
        raise


async def release_ai_request(tenant_id: str) -> None:
    key = f"security-scanner:ai-slots:{hashlib.sha256(tenant_id.encode()).hexdigest()[:20]}"
    await _COUNTER.decrement(key)


def access_token_policy_error(user: Any, token_issued_at: float) -> str | None:
    policy = security_policy(user.tenant_id)
    timeout = int(policy["session_timeout_minutes"])
    age = datetime_from_timestamp(utcnow(), token_issued_at)
    if age > timeout * 60:
        return "Access session expired by tenant security policy"
    return None


def datetime_from_timestamp(now, issued_at: float) -> float:
    return max(0.0, now.timestamp() - float(issued_at))


def failed_login_blocked(user: Any) -> bool:
    policy = security_policy(user.tenant_id)
    max_failed = int(policy["max_failed_logins"])
    since = utcnow() - timedelta(minutes=15)
    with session_scope(user.tenant_id) as db:
        count = db.scalar(select(func.count()).select_from(SecurityEventRow).where(
            SecurityEventRow.tenant_id == user.tenant_id,
            SecurityEventRow.actor_user_id == user.user_id,
            SecurityEventRow.event_type == "auth.login_failed",
            SecurityEventRow.created_at >= since,
        )) or 0
    return int(count) >= max_failed


def enforce_session_limit(user: Any) -> None:
    policy = security_policy(user.tenant_id)
    maximum = int(policy["max_concurrent_sessions"])
    now = utcnow()
    with session_scope(user.tenant_id) as db:
        rows = db.scalars(select(RefreshTokenRow).where(
            RefreshTokenRow.user_id == user.user_id,
            RefreshTokenRow.tenant_id == user.tenant_id,
            RefreshTokenRow.revoked.is_(False),
            RefreshTokenRow.expires_at > now,
        ).order_by(RefreshTokenRow.created_at.desc())).all()
        for old in rows[maximum - 1:]:
            old.revoked = True
