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
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

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
    assessment,
    import_findings,
    template_marketplace,
    oob,
)
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.database import init_db_with_retry, engine, async_engine, JobRow, ScanRow, session_scope_sync, utcnow, with_db_retry


logger = logging.getLogger("security_scanner")
from app.core.file_logging import setup_file_logging
setup_file_logging("backend")


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


if settings.ENVIRONMENT == "production" and not settings.SUPABASE_URL:
    sys.exit(
        "خطأ إعداد قاتل: SUPABASE_URL مطلوب — Supabase Auth هو مزوّد "
        "المصادقة الوحيد المدعوم الآن."
    )


# ---------------------------------------------------------------------------
# Supabase self-service signup
# ---------------------------------------------------------------------------
#
# لا نمنع تشغيل التطبيق عندما تكون:
#
#   SUPABASE_AUTO_PROVISION=true
#   SUPABASE_ALLOW_SELF_SERVICE_SIGNUP=true
#
# لأن المشروع يدعم التسجيل الذاتي.
#
# الأمان لا يعتمد على منع تشغيل التطبيق، بل على مسار المصادقة والصلاحيات:
#
#   مستخدم جديد
#       ↓
#   Supabase Auth
#       ↓
#   إنشاء المستخدم في قاعدة البيانات
#       ↓
#   role = viewer
#       ↓
#   لا يستطيع رفع صلاحياته بنفسه
#       ↓
#   Admin فقط يستطيع تغيير الدور
#
# لذلك تم intentionally حذف شرط startup الذي كان يمنع التطبيق من العمل
# عندما يكون self-service signup مفعلاً.
# ---------------------------------------------------------------------------


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

    ملاحظة مهمة:
    Swagger UI وReDoc يحتاجان إلى تحميل وتشغيل JavaScript/CSS.
    لذلك لا نطبّق CSP الصارمة على /docs و /redoc.
    """

    DOCUMENTATION_PATHS = {
        "/docs",
        "/redoc",
    }

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        response = await call_next(request)

        # -------------------------------------------------------------------
        # Content Security Policy
        # -------------------------------------------------------------------

        if request.url.path not in self.DOCUMENTATION_PATHS:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'none'; "
                "form-action 'none'"
            )

        # -------------------------------------------------------------------
        # HSTS — production فقط حتى لا يؤثر على التطوير المحلي عبر HTTP.
        # -------------------------------------------------------------------

        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # -------------------------------------------------------------------
        # Clickjacking protection
        # -------------------------------------------------------------------

        response.headers["X-Frame-Options"] = "DENY"

        # -------------------------------------------------------------------
        # MIME sniffing protection
        # -------------------------------------------------------------------

        response.headers["X-Content-Type-Options"] = "nosniff"

        # -------------------------------------------------------------------
        # Referrer policy
        # -------------------------------------------------------------------

        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )

        # -------------------------------------------------------------------
        # Browser permissions policy
        # -------------------------------------------------------------------

        response.headers["Permissions-Policy"] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=(), "
            "payment=(), "
            "usb=(), "
            "bluetooth=()"
        )

        # -------------------------------------------------------------------
        # تقليل كشف معلومات الخادم.
        # MutableHeaders في Starlette لا يدعم pop().
        # -------------------------------------------------------------------

        if "server" in response.headers:
            del response.headers["server"]

        return response


# ---------------------------------------------------------------------------
# FastAPI application lifespan
# ---------------------------------------------------------------------------

def invalidate_previous_deployment_jobs():
    """Deployment boundary: never resurrect a scan from an older app instance.

    A new backend/worker stack is a new execution epoch. RUNNING jobs are moved
    to CANCEL_REQUESTED so any still-alive old worker sees the durable stop flag;
    PENDING/CANCEL_REQUESTED jobs are finalized as CANCELLED. Historical ScanRow
    records remain available in Scan History, but they can never become the current
    workspace or be picked up by the new worker.
    """
    now = utcnow()
    def _invalidate():
        with session_scope_sync() as db:
            rows = db.query(JobRow).filter(JobRow.status.in_(["RUNNING", "PENDING", "CANCEL_REQUESTED"])).all()
            for row in rows:
                message = "Invalidated at backend deployment startup; previous scan is never resumed"
                if row.status == "RUNNING":
                    row.status = "CANCEL_REQUESTED"
                    row.error_message = message
                    row.heartbeat_at = now
                else:
                    row.status = "CANCELLED"
                    row.error_message = message
                    row.finished_at = now
                    row.lease_owner = None
                    row.lease_until = None
                scan = db.get(ScanRow, row.job_id)
                if scan:
                    scan.status = row.status
                    scan.error_message = message
                    if row.status == "CANCELLED": scan.finished_at = now
            return len(rows)
    try:
        count = with_db_retry(_invalidate)
        if count:
            logger.warning("Deployment startup invalidated %d previous scan job(s)", count)
    except Exception as exc:
        logger.error("Could not invalidate previous scan jobs at deployment startup: %s", exc, exc_info=True)


@asynccontextmanager
async def lifespan(_app):
    if settings.DB_AUTO_CREATE_SCHEMA:
        init_db_with_retry()

    # A fresh application deployment is an explicit lifecycle boundary: no old
    # scan may continue running or be shown as the current workspace.
    invalidate_previous_deployment_jobs()

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
    # Interactive API docs and the OpenAPI schema describe every route to anyone who can
    # reach the server, so they are only served outside production.
    docs_url=None if settings.ENVIRONMENT == "production" else "/docs",
    redoc_url=None if settings.ENVIRONMENT == "production" else "/redoc",
    openapi_url=None if settings.ENVIRONMENT == "production" else "/openapi.json",
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
# 2026-09-19 fix: unhandled-exception CORS gap
# ---------------------------------------------------------------------------
# Starlette's default behaviour for an exception with no registered handler
# is to let it fall through to ServerErrorMiddleware, which sits OUTSIDE
# CORSMiddleware in the stack. That 500 response therefore never passes
# through CORSMiddleware's header injection, so the browser reports it as a
# CORS failure ("MissingAllowOriginHeader") instead of showing the actual
# 500 - which is exactly what a DevTools trace showed happening to
# /api/v1/auth/me during a slow request. Registering a handler for the base
# Exception class routes it through Starlette's ExceptionMiddleware instead,
# which runs INSIDE CORSMiddleware, so the resulting response gets CORS
# headers like any normal response. This does not change what status code
# or body the client sees for a real bug - it only stops that bug from also
# masquerading as a CORS misconfiguration.
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    from fastapi.responses import JSONResponse

    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


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

app.include_router(
    assessment.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    import_findings.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    template_marketplace.router,
    prefix=settings.API_V1_PREFIX,
)

app.include_router(
    oob.router,
    prefix=settings.API_V1_PREFIX,
)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check() -> dict:
    """
    Liveness probe: process is alive and serving HTTP.
    """
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

    2026-09-21 fix (ثغرة 2): engine.connect() و redis.ping() كلاهما
    متزامنَان (blocking). استدعاؤهما مباشرة داخل async def كان يُجمّد
    event loop كامل العملية لمدة connect_timeout (حتى 15 ثانية) عند أي
    تأخير في DNS — مما يُعلّق كل الطلبات الأخرى (auth، jobs، WS).
    run_in_executor ينقل الحظر إلى thread منفصل مع timeout صريح بـ 5 ثوانٍ.
    """
    import asyncio as _asyncio

    nmap_available = (
        shutil.which(settings.NMAP_BINARY_PATH) is not None
    )

    # -----------------------------------------------------------------------
    # Database — non-blocking via executor
    # -----------------------------------------------------------------------

    async def _check_async_db() -> bool:
        try:
            async with async_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def _check_sync_db() -> bool:
        # Startup/migration engine is checked separately for diagnostics; the
        # request-serving readiness decision below uses the async pool.
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return True
        except Exception:
            return False

    def _check_redis() -> bool:
        if not (settings.JOB_QUEUE_ENABLED and settings.REDIS_URL):
            return True
        try:
            import redis as redis_lib
            redis_lib.Redis.from_url(
                settings.REDIS_URL,
                socket_connect_timeout=3,
                socket_timeout=3,
            ).ping()
            return True
        except Exception:
            return False

    _loop = _asyncio.get_event_loop()
    try:
        # This is the same async pool used by API authentication and job
        # endpoints. A healthy sync pool alone is not sufficient readiness.
        db_available = await _asyncio.wait_for(_check_async_db(), timeout=5)
    except _asyncio.TimeoutError:
        db_available = False

    # Keep the sync check as diagnostic context without letting it mask async
    # request-pool exhaustion.
    if db_available:
        try:
            sync_db_available = await _asyncio.wait_for(
                _loop.run_in_executor(None, _check_sync_db), timeout=5
            )
        except Exception:
            # A slow/blocked diagnostic sync-pool check must never escape the
            # readiness endpoint as a 500/ASGI exception. The async pool is the
            # authoritative serving-path check; a timed-out diagnostic check
            # simply makes readiness false until the pool is healthy again.
            sync_db_available = False
    else:
        sync_db_available = False

    # -----------------------------------------------------------------------
    # Redis — non-blocking via executor
    # -----------------------------------------------------------------------

    redis_available = True

    if settings.JOB_QUEUE_ENABLED and settings.REDIS_URL:
        try:
            redis_available = await _asyncio.wait_for(
                _loop.run_in_executor(None, _check_redis), timeout=5
            )
        except _asyncio.TimeoutError:
            redis_available = False

    # -----------------------------------------------------------------------
    # Readiness checks
    # -----------------------------------------------------------------------

    checks = {
        "nmap": nmap_available,
        "database": db_available,
        "database_async_pool": db_available,
        "database_sync_startup_pool": sync_db_available,
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