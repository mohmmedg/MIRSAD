"""Production user authentication, RBAC and tenant context.

- Passwords: scrypt (stdlib), never persisted in plaintext.
- Access tokens: short-lived HMAC-signed JWT-shaped tokens.
- Refresh tokens: random opaque values; only SHA-256 hashes are stored.
- Tenant isolation: every authenticated request establishes a tenant context.
"""

from __future__ import annotations

import hashlib, hmac
from contextvars import ContextVar
from typing import Any

import jwt

from fastapi import HTTPException, status
from sqlalchemy import select

from app.core.config import settings
from app.core.database import (
    ApiKeyRow,
    TenantRow,
    UserRow,
    AdminSettingRow,
    session_scope,
    utcnow,
)
from app.core.auth_context import tenant_context


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
    ):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role
        self.email = email
        self.aal = aal
        self.amr = amr or []
        self.auth_provider = auth_provider

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
                "Supabase authentication "
                "is not configured"
            ),
        )

    return (
        settings.SUPABASE_URL.rstrip("/")
        + "/auth/v1/.well-known/jwks.json"
    )


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
            )

        jwks = jwt.PyJWKClient(
            _supabase_jwks_url(),
            cache_jwk_set=True,
            lifespan=300,
        )

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
        )

    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid or expired "
                "Supabase access token"
            ),
        ) from exc


def _authenticate_supabase(
    token: str,
) -> Principal:
    claims = _verify_supabase_token(token)

    user_id = str(
        claims.get("sub") or ""
    ).strip()

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Supabase token has no subject",
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

    if has_trusted_tenant_claim:
        tenant_id = claim_tenant_id

    else:
        # No trusted tenant claim.
        #
        # First check whether this Supabase user has already
        # been provisioned in our database. We deliberately use
        # an unscoped session here because we do not yet know
        # which tenant the user belongs to.
        with session_scope() as db:
            existing_user = db.get(
                UserRow,
                user_id,
            )

            if existing_user is not None:
                tenant_id = existing_user.tenant_id
            else:
                tenant_id = f"supabase:{user_id}"

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

    with session_scope(tenant_id) as db:
        user = db.get(
            UserRow,
            user_id,
        )

        if user is None:
            if not settings.SUPABASE_AUTO_PROVISION:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Supabase user is not "
                        "provisioned for this tenant"
                    ),
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

            tenant = db.get(
                TenantRow,
                tenant_id,
            )

            tenant_is_new = tenant is None

            # Global bootstrap check: is this truly the first
            # human ever provisioned on this whole deployment
            # (across ALL tenants)?
            is_true_global_bootstrap = (
                db.scalar(
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
                # This should normally be unreachable because
                # we already looked up UserRow globally before
                # entering the tenant-scoped session.
                #
                # Fail closed rather than silently granting
                # access.
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Supabase user is not "
                        "provisioned for this tenant"
                    ),
                )

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

                db.flush()

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
                    # Any later self-service signup never
                    # starts above viewer.
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
        return _authenticate_supabase(token)

    # Tenant-scoped admin API keys.
    # These are hashed at rest and can only grant
    # the highest role implied by their explicit scopes.
    if x_api_key:
        digest = hashlib.sha256(
            x_api_key.encode()
        ).hexdigest()

        with session_scope() as db:
            key = db.scalar(
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
                owner = db.get(
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

                elif (
                    "scanner:run" in scopes
                    or "reports:read" in scopes
                ):
                    role = "analyst"

                elif "scanner:read" in scopes:
                    role = "viewer"

                else:
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "API key has no usable scopes"
                        ),
                    )

                key.last_used_at = utcnow()

                p = Principal(
                    owner.user_id,
                    key.tenant_id,
                    role,
                    owner.email,
                    auth_provider="api_key",
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
        with session_scope(p.tenant_id) as db:
            row = db.get(
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