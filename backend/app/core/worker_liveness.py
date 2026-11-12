"""Worker-process liveness signals, independent of scan execution."""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("mirsad.worker.liveness")
HEARTBEAT_KEY_PREFIX = "mirsad:worker:heartbeat:"


def _write_heartbeat_file(path: str | Path, timestamp: float) -> None:
    heartbeat_path = Path(path)
    heartbeat_path.write_text(f"{timestamp:.6f}", encoding="ascii")


async def worker_liveness_loop(
    redis_client: Any,
    worker_id: str,
    stop: asyncio.Event,
    *,
    heartbeat_path: str | Path = "/tmp/worker_heartbeat",
    interval_seconds: float = 10.0,
    ttl_seconds: int = 45,
) -> None:
    """Refresh file and Redis heartbeats even while the dispatcher awaits jobs.

    The loop is deliberately independent of the Redis-stream polling loop. If
    the event loop itself deadlocks, both heartbeats stop and health checks can
    detect the genuinely unhealthy process.
    """
    key = f"{HEARTBEAT_KEY_PREFIX}{worker_id}"
    try:
        while not stop.is_set():
            timestamp = time.time()
            try:
                await asyncio.to_thread(_write_heartbeat_file, heartbeat_path, timestamp)
            except OSError:
                logger.debug("Could not update worker heartbeat file", exc_info=True)
            try:
                await asyncio.to_thread(redis_client.set, key, str(timestamp), ex=ttl_seconds)
            except Exception:
                logger.debug("Could not publish worker Redis heartbeat", exc_info=True)
            try:
                await asyncio.wait_for(stop.wait(), timeout=max(0.1, interval_seconds))
            except asyncio.TimeoutError:
                continue
    finally:
        try:
            await asyncio.to_thread(redis_client.delete, key)
        except Exception:
            # Redis TTL remains the fallback if graceful cleanup cannot reach Redis.
            logger.debug("Could not remove worker heartbeat on shutdown", exc_info=True)


def read_worker_heartbeat_status(
    redis_client: Any,
    *,
    now: float | None = None,
    max_age_seconds: float = 45.0,
) -> dict[str, Any]:
    """Return only fresh, parseable worker heartbeats from Redis."""
    current_time = time.time() if now is None else float(now)
    ages: list[float] = []
    for key in redis_client.scan_iter(match=f"{HEARTBEAT_KEY_PREFIX}*", count=100):
        try:
            timestamp = float(redis_client.get(key))
        except (TypeError, ValueError, OverflowError):
            continue
        age = current_time - timestamp
        # Permit a small clock skew but reject future-dated or stale records.
        if -5.0 <= age <= max_age_seconds:
            ages.append(max(0.0, age))
    return {
        "up": bool(ages),
        "worker_count": len(ages),
        "heartbeat_age_seconds": round(min(ages), 1) if ages else None,
    }
