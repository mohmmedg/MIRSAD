"""
main.py

نقطة دخول تطبيق FastAPI. تشغيل محلي:
    uvicorn app.main:app --reload

بعد التشغيل، وثائق الـ API التفاعلية متوفرة على:
    http://127.0.0.1:8000/docs
"""

import logging
import shutil
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

try:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
except ImportError:
    RateLimitExceeded = type("RateLimitExceeded", (Exception,), {})

    async def _rate_limit_exceeded_handler(request, exc):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
        )


from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api.routes import (
    analysis,
    api_security,
    network,
    scans,
    web,
    platform,
    jobs,
    continuous,
    auth,
    admin,
    compliance,
)
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.database import init_db_with_retry, engine


logger = logging.getLogger("security_scanner")


# ---------------------------------------------------------------------------
# Fail-closed configuration checks
# ---------------------------------------------------------------------------

# ENFORCE_TARGET_SCOPE intentionally remains configurable in production.
#
# When ENFORCE_TARGET_SCOPE=false:
#   - ALLOWED_TARGETS is not required.
#   - Users can provide targets directly to the scanner.
#   - SSRF protection remains active independently.
#
# When ENFORCE_TARGET_SCOPE=true:
#   - Targets must pass the ALLOWED_TARGETS scope authorization.
#
# Therefore, there is intentionally NO production startup check forcing
# ENFORCE_TARGET_SCOPE=true.

if settings.ENVIRONMENT == "production" and not settings.REDIS_URL:
    sys.exit(
        "خطأ إعداد قاتل: REDIS_URL مطلوب في production لأن جميع jobs "
        "وContinuous ASM يجب أن تعمل عبر الـdurable worker."
    )

if settings.ENVIRONMENT == "production" and not settings.SCHEDULER_DATABASE_URL:
    sys.exit(
        "خطأ إعداد قاتل: SCHEDULER_DATABASE_URL مطلوب في production. "
        "يجب أن يشير إلى اتصال PostgreSQL قادر على قراءة/تحديث "
        "continuous_schedules عبر جميع الـtenants "
        "(دور privileged/BYPASSRLS مخصص للسcheduler فقط)."
    )

if (
    settings.ENVIRONMENT == "production"
    and not settings.SUPABASE_URL
):
    sys.exit(
        "خطأ إعداد قاتل: SUPABASE_URL مطلوب — Supabase Auth هو مزوّد "
        "المصادقة الوحيد المدعوم الآن."
    )

if (
    settings.ENVIRONMENT == "production"
    and settings.SUPABASE_AUTO_PROVISION
    and settings.SUPABASE_ALLOW_SELF_SERVICE_SIGNUP
):
    sys.exit(
        "خطأ إعداد قاتل: SUPABASE_ALLOW_SELF_SERVICE_SIGNUP=true يسمح لأي "
        "زائر غير مسجّل بإنشاء tenant خاص فيه علناً في production. "
        "عطّلها إلا إذا كنت فعلاً تبني منصة SaaS متعددة المستأجرين تريد بها "
        "self-signup علني (وحتى حينها، المستخدمون الجدد يُنشؤون بدور "
        "viewer فقط أبداً owner/admin)."
    )

if (
    settings.ENVIRONMENT == "production"
    and settings.ENABLE_LEGACY_API_KEY
    and not settings.API_KEY
):
    sys.exit(
        "خطأ إعداد قاتل: ENABLE_LEGACY_API_KEY=true لكن API_KEY غير مضبوط."
    )

if "*" in settings.cors_origins and settings.ENVIRONMENT == "production":
    sys.exit(
        "خطأ إعداد قاتل: CORS_ORIGINS يحوي '*' بينما ENVIRONMENT=production. "
        "حدد نطاقات الـ frontend الفعلية صراحة."
    )


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    إضافة ترويسات أمان قياسية إلى جميع استجابات التطبيق.

    الهدف:
    - تقليل مخاطر XSS وحقن المحتوى.
    - منع clickjacking.
    - منع MIME sniffing.
    - تقليل تسريب معلومات الإحالة.
    - تقليل صلاحيات ميزات المتصفح.
    - فرض HTTPS في بيئة الإنتاج.
    - تقليل كشف معلومات الخادم.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'none'"
        )

        # HSTS — production فقط حتى لا يؤثر على التطوير المحلي عبر HTTP.
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"

        # MIME sniffing protection
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer policy
        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )

        # Browser permissions policy
        response.headers["Permissions-Policy"] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=(), "
            "payment=(), "
            "usb=(), "
            "bluetooth=()"
        )

        # تقليل كشف معلومات الخادم.
        # MutableHeaders في Starlette لا يدعم pop().
        if "server" in response.headers:
            del response.headers["server"]

        return response


from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_app):
    if settings.DB_AUTO_CREATE_SCHEMA:
        init_db_with_retry()

    # Continuous ASM ownership belongs exclusively to the durable worker.
    # API replicas must never recreate in-process scheduler tasks.
    yield


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    lifespan=lifespan,
    title=settings.APP_NAME,
    description=(
        "AI-Powered Comprehensive Security Scanner — "
        "Network & Web Vulnerability Assessment"
    ),
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
    ],
)


# ---------------------------------------------------------------------------
# API routers
# ---------------------------------------------------------------------------

app.include_router(
    auth.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    network.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    web.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    api_security.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    analysis.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    scans.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    platform.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    jobs.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    continuous.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    admin.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    compliance.router,
    prefix=settings.API_V1_PREFIX,
)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check() -> dict:
    """Liveness probe: process is alive and serving HTTP."""
    return {
        "status": "ok",
        "environment": settings.ENVIRONMENT,
    }


# ---------------------------------------------------------------------------
# Readiness check
# ---------------------------------------------------------------------------

@app.get("/readiness")
async def readiness_check() -> dict:
    """
    Readiness probe for orchestrators/CI.

    The API is ready only when the configured Nmap binary is available.
    Gemini is intentionally not required: AI is an optional analysis layer.
    """

    nmap_available = (
        shutil.which(settings.NMAP_BINARY_PATH) is not None
    )

    db_available = True

    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception:
        db_available = False

    redis_available = True

    if settings.JOB_QUEUE_ENABLED and settings.REDIS_URL:
        try:
            import redis as redis_lib

            redis_lib.Redis.from_url(
                settings.REDIS_URL
            ).ping()
        except Exception:
            redis_available = False

    checks = {
        "nmap": nmap_available,
        "database": db_available,
        "redis": redis_available,
    }

    ready = all(checks.values())

    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "not_ready",
            "checks": checks,
        },
    )