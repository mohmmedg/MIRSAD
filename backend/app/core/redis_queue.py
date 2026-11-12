"""Durable Redis Streams job transport with ACK, reclaim and DLQ semantics."""
from __future__ import annotations
import json
import time
from typing import Any
from app.core.config import settings

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

STREAM = "mirsad:scan-jobs:v2"
GROUP = "workers"
DLQ = "mirsad:scan-jobs:dlq:v2"
VISIBILITY_MS = 120_000
MAX_ATTEMPTS = 5
RECOVERY_MARKER_TTL_SECONDS = 300

def recovery_marker_key(job_id: str) -> str:
    """Short-lived deduplication key for DB-to-Redis pending-job recovery."""
    return f"mirsad:scan-job-recovery:{job_id}"

def enqueue_recovery_once(r, job_id: str, ttl_seconds: int = RECOVERY_MARKER_TTL_SECONDS) -> bool:
    """Enqueue a recovery delivery once per short window across worker replicas.

    Redis Streams are at-least-once; this marker only prevents the periodic DB
    reconciliation loop from appending the same PENDING job every 30 seconds.
    The TTL allows recovery again if a delivery was lost outside normal stream
    reclaim (for example after Redis data loss or manual stream cleanup).
    """
    key = recovery_marker_key(job_id)
    if not r.set(key, "1", nx=True, ex=max(60, int(ttl_seconds))):
        return False
    try:
        enqueue(r, job_id, "pending-recovery")
    except Exception:
        try:
            r.delete(key)
        except Exception:
            pass
        raise
    return True

def client():
    if not settings.REDIS_URL or redis is None:
        return None
    return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True,
        socket_connect_timeout=2, socket_timeout=5, health_check_interval=30)

def ensure_group(r):
    try:
        r.xgroup_create(STREAM, GROUP, id="0-0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

def enqueue(r, job_id: str, job_type: str = "scan") -> str:
    ensure_group(r)
    return r.xadd(STREAM, {"job_id": job_id, "job_type": job_type, "enqueued_at": str(time.time())})

def read(r, consumer: str, count: int = 1, block_ms: int = 2000):
    ensure_group(r)
    rows = r.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=count, block=block_ms)
    return rows[0][1] if rows else []

def reclaim(r, consumer: str, min_idle_ms: int = VISIBILITY_MS, count: int = 20):
    ensure_group(r)
    try:
        result = r.xautoclaim(STREAM, GROUP, consumer, min_idle_ms, start_id="0-0", count=count)
        return result[1] if len(result) > 1 else []
    except (AttributeError, redis.ResponseError):
        return []

def ack(r, message_id: str):
    r.xack(STREAM, GROUP, message_id)

def dead_letter(r, message_id: str, fields: dict[str, Any], reason: str):
    payload = dict(fields)
    payload["reason"] = reason[:1000]
    payload["failed_at"] = str(time.time())
    r.xadd(DLQ, payload)
    ack(r, message_id)
