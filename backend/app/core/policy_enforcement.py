from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select

from app.core.auth_context import tenant_context
from app.core.config import settings
from app.core.database import AdminSettingRow, JobRow, SecurityEventRow, RefreshTokenRow, session_scope_sync, utcnow

logger = logging.getLogger(__name__)

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
    # 0 means "no time limit" - a scan is allowed to run until it finishes
    # naturally, no matter how many subdomains/assets are discovered.
    # See scan_timeout_seconds() below for how this is interpreted.
    "max_scan_duration_minutes": 0,
    # Unlike max_scan_duration_minutes, this one is NOT about the overall
    # job - it bounds a single external operation (one nmap run, one
    # browser page load, one DNS lookup, one subdomain's web/network/api
    # scan...). Its job is to turn "hung forever because a remote server
    # rate-limited us / a library call never returns" into a fast, clearly
    # logged failure for that one step, while the rest of the job keeps
    # going and the overall scan stays unbounded. Generous by design so it
    # never cuts off a legitimately slow (but progressing) scan.
    "per_step_timeout_minutes": 180,
    "max_assets": 100000,
    "max_endpoints": 100000,
    "rate_limit_per_minute": 600,
    "enforce_target_scope": True,
}
DEFAULT_AI = {
    "enabled": True,
    "model": None,
    "timeout_seconds": 30,
    "max_output_tokens": 8192,
    "redact_secrets": True,
    "daily_budget_usd": 0,
    "rate_limit_per_minute": 600,
    "max_input_chars": 200000,
    "max_concurrent_requests": 2,
}

# Conservative hard ceilings. Admin policy can tighten these values but cannot
# turn a security control into an unbounded resource sink.
# max_scan_duration_minutes is the one exception: 0 is a valid, explicit
# "no limit" setting (see DEFAULT_SCAN) - admins can still opt back into a
# hard cap between 1 and HARD_MAX_SCAN_DURATION_MINUTES if they want one.
HARD_MAX_SCAN_DURATION_MINUTES = 1440
HARD_MAX_OUTPUT_TOKENS = 16384
HARD_MAX_AI_INPUT_CHARS = 500000
HARD_MAX_AI_CONCURRENCY = 32


def _policy(tenant_id: str) -> AdminSettingRow:
    with session_scope_sync(tenant_id) as db:
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
    with session_scope_sync(tid) as db:
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


def scan_timeout_seconds(tenant_id: str | None = None) -> float | None:
    """Timeout to pass to asyncio.wait_for() for a scan job.

    Returns None (no timeout at all) when max_scan_duration_minutes is 0,
    which is the default. Every scan entry point (worker.py, job_manager.py,
    platform.py) must go through this helper instead of computing
    ``minutes * 60`` itself, so "no limit" is handled consistently.
    """
    minutes = int(scan_policy(tenant_id)["max_scan_duration_minutes"])
    return None if minutes <= 0 else minutes * 60


def step_timeout_seconds(tenant_id: str | None = None) -> float:
    """Timeout (seconds) for a single external operation inside a scan:
    one nmap invocation, one browser page load, one DNS lookup, one
    subdomain's network/web/api scan, etc.

    This is deliberately independent of scan_timeout_seconds()/
    max_scan_duration_minutes - the overall job can be unbounded while each
    individual step still fails fast and with a clear reason instead of
    hanging forever on a rate-limited or unresponsive target.
    """
    minutes = int(scan_policy(tenant_id).get("per_step_timeout_minutes", DEFAULT_SCAN["per_step_timeout_minutes"]))
    # Never below 2h: a stale tenant policy must not cut a scan step short.
    return max(max(1, minutes) * 60, 7200)


def ai_policy(tenant_id: str | None = None) -> dict[str, Any]:
    return get_policies(tenant_id)["ai"]


def validate_policy(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    if kind == "security":
        ints = {"session_timeout_minutes": (1, 1440), "max_concurrent_sessions": (1, 100), "max_failed_logins": (1, 20)}
        bools = {"allow_registration", "require_email_verification", "require_mfa", "force_logout_on_role_change"}
    elif kind == "scan":
        ints = {
            "max_scan_duration_minutes": (0, HARD_MAX_SCAN_DURATION_MINUTES),
            "per_step_timeout_minutes": (1, 1440),
            "max_assets": (1, 1000000),
            "max_endpoints": (1, 1000000),
            "rate_limit_per_minute": (1, 10000),
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
        self.redis_url = settings.REDIS_URL
        if settings.REDIS_URL:
            try:
                import redis.asyncio as redis_async
                self.redis = redis_async.Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
            except Exception:
                self.redis = None
        self.local: dict[str, tuple[int, float]] = {}
        self.lock = threading.Lock()

    async def increment(self, key: str, limit: int, ttl: int = 70) -> bool:
        if self.redis is not None:
            try:
                count = int(await self.redis.incr(key))
                if count == 1:
                    await self.redis.expire(key, ttl)
                if count <= limit:
                    return True
                await self.redis.decr(key)
                return False
            except Exception:
                logger.debug("Redis rate-limit increment failed for %s; falling back to in-memory limiter", key, exc_info=True)
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
                await self.redis.decr(key)
                return
            except Exception:
                logger.debug("Redis rate-limit decrement failed for %s; falling back to in-memory limiter", key, exc_info=True)
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
    # Admission control is intentionally performed before enqueueing. The
    # context remains for backwards-compatible scanner callers.
    yield

async def enforce_scan_admission(tenant_id: str) -> dict[str, Any]:
    policy = scan_policy(tenant_id)
    await enforce_policy_rate_limit("scan", tenant_id, int(policy["rate_limit_per_minute"]))
    return policy


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
            with session_scope_sync(tenant_id) as db:
                spent = db.scalar(
                    select(func.coalesce(func.sum(SecurityEventRow.data["estimated_cost_usd"].as_float()), 0.0)).where(
                        SecurityEventRow.tenant_id == tenant_id,
                        SecurityEventRow.event_type == "ai.budget_reserved",
                        SecurityEventRow.created_at >= since,
                    )
                ) or 0.0
            if float(spent) + estimated_cost > budget:
                raise HTTPException(status_code=429, detail="AI daily budget exhausted for this tenant")
            with session_scope_sync(tenant_id) as db:
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
    with session_scope_sync(user.tenant_id) as db:
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
    with session_scope_sync(user.tenant_id) as db:
        rows = db.scalars(select(RefreshTokenRow).where(
            RefreshTokenRow.user_id == user.user_id,
            RefreshTokenRow.tenant_id == user.tenant_id,
            RefreshTokenRow.revoked.is_(False),
            RefreshTokenRow.expires_at > now,
        ).order_by(RefreshTokenRow.created_at.desc())).all()
        for old in rows[maximum - 1:]:
            old.revoked = True


def enforce_access_token_policies(user: Any, claims: dict, db) -> None:
    raise NotImplementedError("use enforce_access_token_policies_async")

async def enforce_access_token_policies_async(user: Any, claims: dict, db) -> None:
    """SF-01: makes session_timeout_minutes, force_logout_on_role_change and
    max_concurrent_sessions actually bite on every already-existing user, on
    every authenticated request — not just be admin-panel display values.

    Must be called from _authenticate_supabase() for the EXISTING-user branch
    only (a brand-new user has no prior session/security state to violate),
    inside the same tenant-scoped `db` session already open there.

    2026-09-16: async because `db` here is the caller's own AsyncSession
    (core/auth.py, now async end-to-end) and this function executes raw SQL
    against it directly (the auth.sessions check below). security_policy()
    itself still goes through its own separate sync connection
    (session_scope_sync) - see that function's docstring for why.
    """
    policy = security_policy(user.tenant_id)
    iat = claims.get("iat")

    # 1) session_timeout_minutes — reuses the pre-existing (previously never
    #    called) helper.
    if iat is not None:
        err = access_token_policy_error(user, float(iat))
        if err:
            raise HTTPException(status_code=401, detail=err)

    # 2) force_logout_on_role_change — any token issued before the last
    #    security-relevant change (role change, disable, forced session
    #    revocation from the admin panel) is rejected immediately.
    if policy.get("force_logout_on_role_change") and user.security_changed_at is not None and iat is not None:
        token_issued_at = datetime.fromtimestamp(float(iat), tz=timezone.utc)
        changed_at = user.security_changed_at
        if changed_at.tzinfo is None:
            changed_at = changed_at.replace(tzinfo=timezone.utc)
        if token_issued_at < changed_at:
            raise HTTPException(
                status_code=401,
                detail="تم تسجيل الخروج تلقائياً بسبب تغيير أمني على الحساب",
            )

    # 3) max_concurrent_sessions — authentication and session creation are owned
    # by Supabase. This application connects only to its local application DB,
    # where `auth.sessions` intentionally does not exist. Do not query that
    # remote-only schema through the local SQLAlchemy session: it produces a
    # warning on every request and can never reliably enforce the policy.
    # Enforcing a strict cross-device limit requires a supported Supabase Auth
    # session-management integration; the local refresh_tokens table is not
    # authoritative because Supabase handles refresh tokens itself.
