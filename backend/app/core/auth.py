"""Production user authentication, RBAC and tenant context.

- Passwords: scrypt (stdlib), never persisted in plaintext.
- Access tokens: short-lived HMAC-signed JWT-shaped tokens.
- Refresh tokens: random opaque values; only SHA-256 hashes are stored.
- Tenant isolation: every authenticated request establishes a tenant context.
"""

from __future__ import annotations

import hashlib, hmac
import logging
import sys
import time
from contextvars import ContextVar
from typing import Any

import anyio.to_thread
import jwt

from fastapi import HTTPException, status
from sqlalchemy import func, select

from app.core.config import settings
from app.core.database import (
    ApiKeyRow,
    TenantRow,
    UserRow,
    AdminSettingRow,
    session_scope,
    utcnow,
    with_db_retry_async,
)
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import enforce_access_token_policies_async

logger = logging.getLogger(__name__)


_current: ContextVar["Principal | None"] = ContextVar(
    "current_principal",
    default=None,
)


class Principal:
    def __init__(
        self,
        user_id: str,
        tenant_id: str,
        role: str,
        email: str,
        aal: str = "aal1",
        amr: list[str] | None = None,
        auth_provider: str = "local",
        scopes: set[str] | None = None,
    ):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role
        self.email = email
        self.aal = aal
        self.amr = amr or []
        self.auth_provider = auth_provider
        self.scopes = set(scopes or [])

    def as_dict(self):
        return {
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "email": self.email,
            "aal": self.aal,
            "amr": self.amr,
        }


ROLE_RANK = {
    "viewer": 10,
    "analyst": 20,
    "admin": 30,
    "owner": 40,
}


def current_principal() -> Principal:
    p = _current.get()
    if not p:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )
    return p


def set_principal(p: Principal):
    _current.set(p)


# ملاحظة: كل دوال المصادقة المحلية (JWT محلي موقّع بـ HMAC، تجزئة كلمات
# المرور، إصدار access/refresh tokens محلياً) أُزيلت بالكامل. المصادقة
# الآن تمر حصراً عبر Supabase Auth — انظر _authenticate_supabase أدناه.


def _nested_claim(
    payload: dict[str, Any],
    path: str,
) -> Any:
    value: Any = payload

    for part in path.split("."):
        if not isinstance(value, dict):
            return None

        value = value.get(part)

    return value


def _supabase_jwks_url() -> str:
    if not settings.SUPABASE_URL:
        raise HTTPException(
            status_code=503,
            detail=(
                "خدمة المصادقة "
                "is not configured"
            ),
        )

    return (
        settings.SUPABASE_URL.rstrip("/")
        + "/auth/v1/.well-known/jwks.json"
    )


# ---------------------------------------------------------------------------
# JWKS client cache
# ---------------------------------------------------------------------------
#
# jwt.PyJWKClient(..., cache_jwk_set=True) only caches signing keys for the
# lifetime of the *instance itself*. Creating a brand-new PyJWKClient inside
# _verify_supabase_token() on every single call — as this used to do —
# silently defeats that cache: every authenticated request (and this app is
# polled multiple times per second by the scan-progress UI) then performs a
# fresh network round-trip to Supabase's JWKS endpoint. Under load this
# hammers Supabase and produces exactly the intermittent failures seen in
# production logs:
#   PyJWKClientConnectionError: ... HTTP Error 504: Gateway Timeout
# which in turn surface to users as random 401s on an otherwise-valid
# session. Keeping one PyJWKClient per JWKS URL for the life of the process
# restores the intended caching behaviour (a real network fetch only every
# `lifespan` seconds, or when an unrecognized `kid` is seen).
_jwks_clients: dict[str, "jwt.PyJWKClient"] = {}


def _get_jwks_client(jwks_url: str) -> "jwt.PyJWKClient":
    client = _jwks_clients.get(jwks_url)
    if client is None:
        # 2026-09-18 fix: PyJWKClient يستخدم urllib بدون مهلة افتراضية. لو
        # تأخّر (أو حُجب) مضيف Supabase، يبقى الطلب معلّقاً بلا نهاية —
        # وهذا ما يجعل GET /api/v1/auth/me لا يردّ أبداً، فتقطعه الواجهة
        # وتظهر "signal is aborted without reason". مهلة صريحة تحوّل هذا
        # إلى 401 سريع ومفهوم بدل تعليق صامت.
        client = jwt.PyJWKClient(
            jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=int(getattr(settings, "SUPABASE_JWKS_TIMEOUT_SECONDS", 5)),
        )
        _jwks_clients[jwks_url] = client
    return client


def _verify_supabase_token(
    token: str,
) -> dict[str, Any]:
    try:
        issuer = (
            settings.SUPABASE_JWT_ISSUER
            or (
                settings.SUPABASE_URL.rstrip("/")
                + "/auth/v1"
                if settings.SUPABASE_URL
                else None
            )
        )

        if not issuer:
            raise ValueError("missing issuer")

        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")

        if (
            algorithm == "HS256"
            and settings.SUPABASE_JWT_SECRET
        ):
            return jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience=settings.SUPABASE_JWT_AUDIENCE,
                issuer=issuer,
                # Tolerate small clock skew between this container's system
                # clock and Supabase's, so a token is not rejected as
                # "not yet valid" (iat) or "expired" over a few seconds of
                # drift. This does not weaken the check materially — it
                # only widens the accepted window by a few seconds.
                leeway=30,
                options={"require": ["exp", "sub", "aud", "iss"]},
            )

        jwks = _get_jwks_client(_supabase_jwks_url())

        # A slow/dropped connection to Supabase must not look like a bad
        # password: retry the JWKS fetch once, and if it still cannot be
        # reached let the outer handler answer 503 (not 401).
        try:
            key = jwks.get_signing_key_from_jwt(token)
        except jwt.exceptions.PyJWKClientConnectionError:
            time.sleep(0.5)
            key = jwks.get_signing_key_from_jwt(token)

        return jwt.decode(
            token,
            key.key,
            algorithms=[
                "RS256",
                "ES256",
                "EdDSA",
            ],
            audience=settings.SUPABASE_JWT_AUDIENCE,
            issuer=issuer,
            leeway=30,
            options={"require": ["exp", "sub", "aud", "iss"]},
        )

    except jwt.exceptions.PyJWKClientConnectionError as exc:
        print(
            f"[auth] Supabase JWKS unreachable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        raise HTTPException(
            status_code=503,
            detail="Authentication service temporarily unreachable. Please retry.",
        ) from exc
    except Exception as exc:
        print(
            f"[auth] Supabase token verification failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid or expired "
                "Supabase access token"
            ),
        ) from exc


async def _authenticate_supabase(
    token: str,
) -> Principal:
    # 2026-09-18 fix: _verify_supabase_token() متزامنة وقد تنفّذ طلب شبكة
    # حاجز (urllib) لجلب JWKS. استدعاؤها مباشرة داخل معالج async كان يُجمّد
    # حلقة الأحداث بالكامل: طلب واحد بطيء نحو Supabase يُعلّق كل الطلبات
    # الأخرى في الخادم. تشغيلها في خيط منفصل يُبقي الخادم مستجيباً.
    claims = await anyio.to_thread.run_sync(_verify_supabase_token, token)

    user_id = str(
        claims.get("sub") or ""
    ).strip()

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="جلسة الدخول غير صالحة",
        )

    email = str(
        claims.get("email") or ""
    ).strip().lower()

    # ---------------------------------------------------------
    # TENANT RESOLUTION
    # ---------------------------------------------------------
    #
    # If Supabase provides a trusted tenant claim, use it.
    #
    # If the claim is missing, DO NOT automatically assume
    # `supabase:<user_id>` for an already-provisioned user.
    #
    # Instead, look up the user's existing server-side tenant
    # association first. This prevents a valid existing user
    # from receiving "Tenant mismatch" simply because the
    # Supabase JWT does not contain tenant_id.
    #
    # New users without a tenant claim still receive the
    # default `supabase:<user_id>` tenant as before.
    # ---------------------------------------------------------

    claim_tenant_id = str(
        _nested_claim(
            claims,
            settings.SUPABASE_TENANT_CLAIM,
        )
        or ""
    ).strip()

    has_trusted_tenant_claim = bool(
        claim_tenant_id
    )
    personal_tenant_id = f"supabase:{user_id}"

    # The registration form may carry an organization name. The server
    # resolves that name to an existing tenant; the client never supplies
    # or controls tenant_id directly.
    requested_tenant_name = str(
        _nested_claim(claims, "user_metadata.tenant_name")
        or _nested_claim(claims, "app_metadata.tenant_name")
        or ""
    ).strip()
    requested_tenant_name = " ".join(requested_tenant_name.split())
    if not settings.SUPABASE_ALLOW_JOIN_TENANT_BY_NAME:
        # user_metadata is editable by the user themselves; never let it select an
        # EXISTING tenant unless the operator explicitly opted in.
        requested_tenant_name = ""
    requested_tenant_id: str | None = None
    requested_tenant_ambiguous = False
    joining_requested_tenant = False

    if has_trusted_tenant_claim:
        tenant_id = claim_tenant_id

    else:
        # No trusted tenant claim. Existing users always keep their stored
        # tenant association; the registration-time organization name is only
        # consulted when this Supabase identity has not been provisioned yet.
        #
        # 2026-09-21 fix (ثغرة 1): لفّ قراءة DB بـ with_db_retry_async حتى
        # لا يتحوّل أي انقطاع عابر (إعادة تشغيل Supavisor، DNS blip) إلى
        # 500 مباشر على مسار تسجيل الدخول بدل إعادة محاولة صامتة.
        async def _resolve_tenant_from_db() -> tuple[str, bool]:
            async with session_scope() as _db:
                _existing = await _db.get(UserRow, user_id)
                if _existing is not None:
                    return _existing.tenant_id, False
                if requested_tenant_name:
                    _matches = (await _db.scalars(
                        select(TenantRow).where(
                            func.lower(TenantRow.name) == requested_tenant_name.lower()
                        )
                    )).all()
                    if len(_matches) > 1:
                        raise HTTPException(
                            status_code=409,
                            detail="يوجد أكثر من مؤسسة بهذا الاسم. يجب توحيد اسم المؤسسة أولاً.",
                        )
                    if len(_matches) == 1:
                        return _matches[0].tenant_id, True
                return personal_tenant_id, False

        # 2026-10-05: no inner with_db_retry_async here. authenticate_request()
        # already retries this whole function; a nested retry multiplied
        # attempts (5 x 5) and, with a 15s pool timeout, kept connections
        # checked out long enough to exhaust the small QueuePool.
        tenant_id, joining_requested_tenant = await _resolve_tenant_from_db()

    role = str(
        _nested_claim(
            claims,
            settings.SUPABASE_ROLE_CLAIM,
        )
        or "viewer"
    ).lower()

    aal = str(
        claims.get("aal") or "aal1"
    )

    amr_claim = claims.get("amr") or []

    amr = (
        [
            str(x.get("method"))
            if isinstance(x, dict)
            else str(x)
            for x in amr_claim
        ]
        if isinstance(amr_claim, list)
        else []
    )

    if role not in ROLE_RANK:
        role = "viewer"

    # ---------------------------------------------------------
    # NOW THAT tenant_id IS RESOLVED, establish the tenant
    # scoped database context.
    # ---------------------------------------------------------

    async with session_scope(tenant_id) as db:
        user = await db.get(
            UserRow,
            user_id,
        )

        if user is None:
            # Login must NEVER recreate an application user.
            #
            # A missing UserRow is allowed to be provisioned only when this
            # request is establishing a genuinely new tenant (signup flow),
            # or when a trusted tenant claim explicitly places the user into
            # an existing organization.
            #
            # Critical security rule:
            # if the personal tenant already exists but its user row was
            # deleted, do NOT recreate the user during normal login.
            tenant = await db.get(TenantRow, tenant_id)
            tenant_is_new = tenant is None

            if (
                not has_trusted_tenant_claim
                and not tenant_is_new
                and not joining_requested_tenant
            ):
                raise HTTPException(
                    status_code=403,
                    detail="الحساب غير مرتبط بمؤسسة",
                )

            if not settings.SUPABASE_AUTO_PROVISION:
                raise HTTPException(
                    status_code=403,
                    detail="الحساب غير مهيأ للوصول إلى النظام",
                )

            # Was tenant_id derived from a trusted server-side
            # JWT claim (the caller is joining an EXISTING
            # organization), or did it fall back to the
            # per-user default `supabase:<user_id>`?
            #
            # IMPORTANT:
            # At this point a missing claim means the user is
            # genuinely new because we already checked the
            # server-side UserRow above.

            # `tenant` and `tenant_is_new` were resolved above.

            # Global bootstrap check: is this truly the first
            # human ever provisioned on this whole deployment
            # (across ALL tenants)?
            is_true_global_bootstrap = (
                await db.scalar(
                    select(UserRow.user_id)
                    .limit(1)
                )
                is None
            )

            if (
                tenant_is_new
                and not has_trusted_tenant_claim
                and not is_true_global_bootstrap
            ):
                # Someone with no trusted tenant claim trying
                # to self-provision a brand-new tenant, after
                # the system already has an owner.
                if not settings.SUPABASE_ALLOW_SELF_SERVICE_SIGNUP:
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "Self-service tenant creation "
                            "is disabled. Ask an administrator "
                            "for an invite."
                        ),
                    )

                # Explicitly allowed self-service:
                # they get their own tenant, but NEVER as
                # owner/admin.
                tenant_is_new = True

            elif (
                not has_trusted_tenant_claim
                and not tenant_is_new
            ):
                # A signup-created tenant can already exist even when the
                # corresponding application user row was not committed (for
                # example, if provisioning was interrupted after tenant
                # creation). In that case the tenant id is deterministically
                # derived from this user's own id, so this is safe to repair
                # by provisioning the missing user row instead of rejecting
                # the login.
                pass

            if joining_requested_tenant:
                # Joining an existing organization through self-service always
                # creates a viewer. Organization names never grant privileges.
                role = "viewer"

            if not has_trusted_tenant_claim and tenant_id == personal_tenant_id:
                # This user created the isolated tenant derived from its own id.
                # Self-service tenant creators are regular viewers; tenant creation
                # must not implicitly grant administrative privileges.
                role = "viewer"

            if tenant_is_new:
                db.add(
                    TenantRow(
                        tenant_id=tenant_id,
                        name=str(
                            _nested_claim(
                                claims,
                                "app_metadata.tenant_name",
                            )
                            or _nested_claim(
                                claims,
                                "user_metadata.tenant_name",
                            )
                            or tenant_id
                        ),
                        created_at=utcnow(),
                    )
                )

                await db.flush()

                if is_true_global_bootstrap:
                    # One-time-only:
                    # the very first identity on a fresh
                    # deployment becomes owner.
                    claimed_role = str(
                        _nested_claim(
                            claims,
                            settings.SUPABASE_ROLE_CLAIM,
                        )
                        or ""
                    ).lower().strip()

                    role = (
                        claimed_role
                        if claimed_role in ROLE_RANK
                        else "owner"
                    )

                elif not has_trusted_tenant_claim:
                    # A self-service signup creates its own isolated tenant.
                    # The creator is a viewer by default; tenant creation does
                    # not implicitly grant owner/admin privileges.
                    role = "viewer"

                # If has_trusted_tenant_claim is True and this
                # is a brand-new tenant, the tenant is being
                # provisioned by a server-attested flow.
                # The trusted role claim is therefore retained.

            elif not has_trusted_tenant_claim:
                role = "viewer"

            # Create the new provisioned user.
            user = UserRow(
                user_id=user_id,
                tenant_id=tenant_id,
                email=(
                    email
                    or f"{user_id}@supabase.local"
                ),
                password_hash="",
                role=role,
                is_active=True,
                created_at=utcnow(),
            )

            db.add(user)

        else:
            # -------------------------------------------------
            # EXISTING USER
            # -------------------------------------------------
            #
            # At this point tenant_id has already been resolved
            # from:
            #
            #   1. trusted Supabase claim, OR
            #   2. existing UserRow.tenant_id
            #
            # Therefore a normal Supabase JWT without a tenant
            # claim will no longer produce a false mismatch.
            # -------------------------------------------------

            if user.tenant_id != tenant_id:
                raise HTTPException(
                    status_code=403,
                    detail="Tenant mismatch",
                )

            # Server-side RBAC is authoritative after
            # provisioning. A JWT claim must never silently
            # overwrite an administrator's role.
            if email and user.email != email:
                user.email = email

            if not user.is_active:
                raise HTTPException(
                    status_code=403,
                    detail="User account is disabled",
                )

            # SF-01: session_timeout_minutes / force_logout_on_role_change /
            # max_concurrent_sessions were defined in security policy and
            # shown in the admin panel, but never actually enforced on the
            # request path. A brand-new user (the `if user is None` branch
            # above) has no prior session/security state, so this only
            # applies to an already-existing user re-authenticating.
            await enforce_access_token_policies_async(user, claims, db)

        principal = Principal(
            user.user_id,
            user.tenant_id,
            user.role,
            user.email,
            aal=aal,
            amr=amr,
            auth_provider="supabase",
        )

    set_principal(principal)

    return principal



# ---------------------------------------------------------------------------
# Short-lived principal cache (2026-10-05)
# ---------------------------------------------------------------------------
# Every authenticated request used to open 2+ DB sessions. The dashboard polls
# several endpoints every few seconds, so under a scan the tiny QueuePool
# (size 2 + overflow 4 on the free Supabase plan) was exhausted by auth alone
# and /jobs/{id} returned 500 while the scan itself was healthy.
#
# Only SUCCESSFUL authentications are cached, keyed by sha256(token) (the raw
# token is never stored), for min(AUTH_PRINCIPAL_CACHE_SECONDS, token lifetime).
# Role changes / deactivation take effect within that window, or immediately
# when invalidate_principal_cache() is called. 0 disables the cache.
import threading as _threading
from collections import OrderedDict as _OrderedDict

_PRINCIPAL_CACHE: "_OrderedDict[str, tuple[float, Principal]]" = _OrderedDict()
_PRINCIPAL_CACHE_LOCK = _threading.Lock()
_PRINCIPAL_CACHE_MAX = 512


def _principal_cache_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _principal_cache_get(token: str) -> "Principal | None":
    ttl = int(getattr(settings, "AUTH_PRINCIPAL_CACHE_SECONDS", 0) or 0)
    if ttl <= 0:
        return None
    key = _principal_cache_key(token)
    now = time.monotonic()
    with _PRINCIPAL_CACHE_LOCK:
        hit = _PRINCIPAL_CACHE.get(key)
        if not hit:
            return None
        if hit[0] <= now:
            _PRINCIPAL_CACHE.pop(key, None)
            return None
        _PRINCIPAL_CACHE.move_to_end(key)
        return hit[1]


def _principal_cache_put(token: str, principal: "Principal") -> None:
    ttl = int(getattr(settings, "AUTH_PRINCIPAL_CACHE_SECONDS", 0) or 0)
    if ttl <= 0:
        return
    try:
        # Never outlive the JWT itself. The signature was already verified by
        # _authenticate_supabase; here we only read the exp claim.
        exp = jwt.decode(token, options={"verify_signature": False, "verify_exp": False}).get("exp")
        if exp is not None:
            ttl = min(ttl, int(float(exp) - time.time()))
    except Exception:
        return
    if ttl <= 0:
        return
    with _PRINCIPAL_CACHE_LOCK:
        _PRINCIPAL_CACHE[_principal_cache_key(token)] = (time.monotonic() + ttl, principal)
        _PRINCIPAL_CACHE.move_to_end(_principal_cache_key(token))
        while len(_PRINCIPAL_CACHE) > _PRINCIPAL_CACHE_MAX:
            _PRINCIPAL_CACHE.popitem(last=False)


def invalidate_principal_cache() -> None:
    """Drop every cached principal (call after role/active/tenant changes)."""
    with _PRINCIPAL_CACHE_LOCK:
        _PRINCIPAL_CACHE.clear()


async def authenticate_request(
    authorization: str | None,
    x_api_key: str | None,
) -> Principal:
    if (
        authorization
        and authorization.lower().startswith("bearer ")
    ):
        token = authorization.split(
            None,
            1,
        )[1].strip()

        # المصادقة عبر Supabase فقط — لا يوجد بعد الآن أي مزوّد "local".
        # 2026-09-21 fix (ثغرة 1): لفّ _authenticate_supabase بـ retry حتى
        # يتعامل كل مسار محمي (auth/me، jobs/{id}، ...) مع انقطاع DB عابر.
        cached = _principal_cache_get(token)
        if cached is not None:
            set_principal(cached)
            return cached
        principal = await with_db_retry_async(lambda: _authenticate_supabase(token))
        _principal_cache_put(token, principal)
        return principal

    # Tenant-scoped admin API keys.
    # These are hashed at rest and can only grant
    # the highest role implied by their explicit scopes.
    if x_api_key:
        digest = hashlib.sha256(
            x_api_key.encode()
        ).hexdigest()

        async with session_scope() as db:
            key = await db.scalar(
                select(ApiKeyRow).where(
                    ApiKeyRow.key_hash == digest
                )
            )

            if (
                key
                and not key.revoked
                and (
                    key.expires_at is None
                    or key.expires_at > utcnow()
                )
            ):
                owner = await db.get(
                    UserRow,
                    key.user_id,
                )

                if (
                    not owner
                    or not owner.is_active
                    or owner.tenant_id != key.tenant_id
                ):
                    raise HTTPException(
                        status_code=401,
                        detail="API key owner is inactive",
                    )

                scopes = set(
                    key.scopes or []
                )

                if "admin:*" in scopes:
                    role = "admin"
                elif "scanner:run" in scopes:
                    role = "analyst"
                elif scopes:
                    role = "viewer"
                else:
                    raise HTTPException(status_code=403, detail="API key has no usable scopes")

                key.last_used_at = utcnow()

                p = Principal(
                    owner.user_id,
                    key.tenant_id,
                    role,
                    owner.email,
                    auth_provider="api_key",
                    scopes=scopes,
                )

                set_principal(p)

                return p

    # Legacy API keys remain available only when explicitly
    # enabled. They are server-side secrets.
    if (
        x_api_key
        and (
            settings.ENABLE_LEGACY_API_KEY
            or settings.ENVIRONMENT != "production"
        )
        and settings.API_KEY
        and hmac.compare_digest(
            x_api_key,
            settings.API_KEY,
        )
    ):
        tenant = (
            settings.LEGACY_API_KEY_TENANT_ID
            or "legacy"
        )

        p = Principal(
            "legacy-api-key",
            tenant,
            "admin",
            "legacy@local",
        )

        set_principal(p)

        return p

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={
            "WWW-Authenticate": "Bearer"
        },
    )


async def require_role(
    required: str,
    authorization: str | None = None,
    x_api_key: str | None = None,
) -> Principal:
    p = (
        current_principal()
        if current_principal_optional()
        else await authenticate_request(
            authorization,
            x_api_key,
        )
    )

    if (
        ROLE_RANK.get(p.role, 0)
        < ROLE_RANK.get(required, 999)
    ):
        raise HTTPException(
            status_code=403,
            detail="Insufficient role",
        )

    # Dependencies such as require_viewer/require_analyst
    # may be used without verify_api_key in route declarations.
    # Always bind the authenticated principal's tenant before
    # any downstream DB access.
    tenant_context.set(p.tenant_id)

    if (
        required == "admin"
        and p.auth_provider == "supabase"
    ):
        async with session_scope(p.tenant_id) as db:
            row = await db.get(
                AdminSettingRow,
                p.tenant_id,
            )

            policy = (
                row.security_policy
                if row
                else {}
            ) or {}

            if (
                policy.get(
                    "require_mfa",
                    True,
                )
                and p.aal != "aal2"
            ):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "MFA (AAL2) is required "
                        "for administrator access"
                    ),
                )

    return p


async def require_step_up(
    authorization: str | None = None,
    x_api_key: str | None = None,
) -> Principal:
    p = (
        current_principal()
        if current_principal_optional()
        else await authenticate_request(
            authorization,
            x_api_key,
        )
    )

    if p.auth_provider == "api_key":
        raise HTTPException(
            status_code=403,
            detail=(
                "Interactive MFA is required; "
                "API keys cannot perform this "
                "sensitive action"
            ),
        )

    if (
        p.auth_provider == "supabase"
        and p.aal != "aal2"
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Step-up MFA (AAL2) required "
                "for this sensitive action"
            ),
        )

    return p


def current_principal_optional():
    return _current.get()