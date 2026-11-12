"""Redis-backed distributed semaphore for safe multi-worker scan concurrency.

المشكلة اللي يحلها هذا الملف: asyncio.Semaphore عادي يحدد التزامن *داخل
عملية واحدة فقط*. لو شغّلنا عدة worker containers بالتوازي (بالضبط الهدف من
"التوزيع الذكي" لتسريع الفحص)، كل container يحصل على نسخته الخاصة من
الـ semaphore، فالسقف الفعلي يتضاعف بعدد الـ containers بدل ما يبقى ثابت —
وهذا يفتح الباب لضغط غير محسوب على قاعدة البيانات والموقع المفحوص.

هذا الـ semaphore يستخدم Redis (متوفر أصلاً بالمشروع لطابور المهام) كعدّاد
مشترك بين كل العمليات، مع صلاحية زمنية (TTL) على كل حجز حتى لو انهار worker
فجأة (crash / kill -9) العدّاد يتحرر تلقائياً بدل ما يبقى "معلّق" للأبد.

الاستخدام:
    async with distributed_slot("engines:global", limit=settings.MAX_CONCURRENT_ENGINES):
        async with distributed_slot(f"engines:target:{target_key}", limit=settings.MAX_CONCURRENT_ENGINES_PER_TARGET):
            await run_the_actual_scan()

لو REDIS_URL غير مفعّل (بيئة تطوير محلية بدون Redis)، يتحول تلقائياً لسلوك
"بدون حد" (no-op) بدل ما يفشل الفحص بالكامل — نفس فلسفة rate_limit.py
الموجودة بالمشروع.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from app.core.config import settings

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

logger = logging.getLogger("mirsad.distributed_semaphore")

_KEY_PREFIX = "mirsad:sem:"
_SLOT_TTL_SECONDS = 180          # صلاحية الحجز؛ يُجدَّد دورياً طالما الفحص شغال
_ACQUIRE_POLL_SECONDS = 1.0
_RENEW_INTERVAL_SECONDS = 60

# Lua: يحجز مكان فقط لو العدد الحالي من المفاتيح غير المنتهية أقل من limit.
# ينظّف المفاتيح المنتهية (expired) ضمن نفس العملية الذرية قبل العد.
_ACQUIRE_LUA = """
local zkey = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', zkey, '-inf', now)
local count = redis.call('ZCARD', zkey)
if count < limit then
    redis.call('ZADD', zkey, now + ttl, member)
    redis.call('EXPIRE', zkey, ttl + 30)
    return 1
end
return 0
"""

_RENEW_LUA = """
local zkey = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local member = ARGV[3]
if redis.call('ZSCORE', zkey, member) then
    redis.call('ZADD', zkey, now + ttl, member)
    redis.call('EXPIRE', zkey, ttl + 30)
end
"""

_client = None
_client_checked = False


def _get_client():
    global _client, _client_checked
    if _client_checked:
        return _client
    _client_checked = True
    if not settings.REDIS_URL or redis is None:
        logger.warning("REDIS_URL not set; distributed concurrency limits are DISABLED (no-op). "
                        "Safe for local/dev only — production must set REDIS_URL.")
        _client = None
        return None
    try:
        _client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True,
                                        socket_connect_timeout=2, socket_timeout=5,
                                        health_check_interval=30)
        _client.ping()
    except Exception as exc:
        logger.error("Distributed semaphore: Redis unavailable (%s); limits are DISABLED for this process.", exc)
        _client = None
    return _client


@asynccontextmanager
async def distributed_slot(name: str, limit: int, *, wait_timeout: float | None = None):
    """يحجز مكان واحد ضمن سقف عالمي مشترك باسم `name`.

    - `name`: مفتاح منطقي، مثلاً "engines:global" أو f"engines:target:{host}".
    - `limit`: أقصى عدد حجوزات فعّالة بنفس اللحظة تحت نفس الاسم.
    - `wait_timeout`: أقصى وقت انتظار (ثانية) قبل ما يستسلم ويرمي TimeoutError.
      None = ينتظر بلا حد (نفس سلوك asyncio.Semaphore العادي).

    لو Redis غير متوفر، يتصرف كـ no-op (يسمح فوراً) — الفحص ما يتوقف بسبب
    مشكلة بنية تحتية جانبية، لكن هذا يعني فقدان الحماية الموزّعة مؤقتاً.
    """
    client = _get_client()
    if client is None:
        yield
        return

    zkey = f"{_KEY_PREFIX}{name}"
    member = uuid.uuid4().hex
    acquire = client.register_script(_ACQUIRE_LUA)
    renew = client.register_script(_RENEW_LUA)

    start = time.monotonic()
    acquired = False
    while not acquired:
        now = time.time()
        ok = await asyncio.to_thread(acquire, keys=[zkey], args=[now, _SLOT_TTL_SECONDS, limit, member])
        acquired = bool(ok)
        if acquired:
            break
        if wait_timeout is not None and (time.monotonic() - start) >= wait_timeout:
            raise TimeoutError(f"Timed out waiting for distributed slot '{name}' (limit={limit})")
        await asyncio.sleep(_ACQUIRE_POLL_SECONDS)

    stop = asyncio.Event()

    async def _renew_loop():
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=_RENEW_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                try:
                    await asyncio.to_thread(renew, keys=[zkey], args=[time.time(), _SLOT_TTL_SECONDS, member])
                except Exception:
                    logger.debug("Failed to renew distributed slot '%s'", name, exc_info=True)

    renew_task = asyncio.create_task(_renew_loop())
    try:
        yield
    finally:
        stop.set()
        renew_task.cancel()
        try:
            await renew_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            await asyncio.to_thread(client.zrem, zkey, member)
        except Exception:
            logger.debug("Failed to release distributed slot '%s'", name, exc_info=True)


def target_key(target: str) -> str:
    """يطبّع اسم الهدف (دومين/URL/IP) لمفتاح Redis ثابت — نفس الهدف بأشكال
    مختلفة (http/https، www، مسار) يجب يصطف على نفس عدّاد الحماية."""
    import re
    host = target.strip().lower()
    host = re.sub(r"^[a-z]+://", "", host)
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]
    host = re.sub(r"^www\.", "", host)
    return host or "unknown"
