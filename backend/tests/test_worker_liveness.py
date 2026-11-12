import asyncio
import time

import pytest

from app.core.worker_liveness import read_worker_heartbeat_status, worker_liveness_loop


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.expiries = {}
        self.set_calls = []
        self.deleted = []

    def set(self, key, value, ex=None):
        self.values[key] = value
        self.expiries[key] = ex
        self.set_calls.append((key, value, ex))
        return True

    def delete(self, key):
        self.deleted.append(key)
        self.values.pop(key, None)
        self.expiries.pop(key, None)
        return 1

    def scan_iter(self, match=None, count=None):
        prefix = match.removesuffix("*") if match else ""
        return (key for key in self.values if key.startswith(prefix))

    def get(self, key):
        return self.values.get(key)


@pytest.mark.asyncio
async def test_worker_liveness_refreshes_while_a_long_scan_is_running(tmp_path):
    redis = FakeRedis()
    stop = asyncio.Event()
    heartbeat_file = tmp_path / "worker_heartbeat"
    task = asyncio.create_task(worker_liveness_loop(
        redis, "worker-1", stop, heartbeat_path=heartbeat_file,
        interval_seconds=0.1, ttl_seconds=45,
    ))

    async def long_scan():
        await asyncio.sleep(0.26)

    await long_scan()
    stop.set()
    await task

    key = "mirsad:worker:heartbeat:worker-1"
    assert len(redis.set_calls) >= 3
    assert all(call[0] == key and call[2] == 45 for call in redis.set_calls)
    assert heartbeat_file.exists()
    assert redis.deleted == [key]


def test_worker_status_ignores_stale_or_malformed_heartbeats():
    redis = FakeRedis()
    now = time.time()
    redis.values = {
        "mirsad:worker:heartbeat:stale": str(now - 90),
        "mirsad:worker:heartbeat:malformed": "not-a-timestamp",
        "mirsad:worker:heartbeat:live": str(now - 4),
    }

    status = read_worker_heartbeat_status(redis, now=now, max_age_seconds=45)

    assert status["worker_count"] == 1
    assert status["up"] is True
    assert status["heartbeat_age_seconds"] == pytest.approx(4, abs=0.1)
