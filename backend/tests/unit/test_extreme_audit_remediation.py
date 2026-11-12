from datetime import datetime, timezone

from app.core import redis_queue
from app.core.database import AssetRow, JobRow


def test_durable_stream_contract_constants():
    assert redis_queue.STREAM.endswith(":v2")
    assert redis_queue.GROUP == "workers"
    assert redis_queue.DLQ.endswith(":dlq:v2")
    assert redis_queue.MAX_ATTEMPTS >= 3
    assert redis_queue.VISIBILITY_MS >= 60_000


def test_job_model_contains_lease_and_heartbeat_fields():
    for name in ("heartbeat_at", "lease_owner", "lease_until", "attempt_count"):
        assert hasattr(JobRow, name)


def test_asset_model_has_tenant_identity_contract():
    assert hasattr(AssetRow, "canonical_identity")
    assert hasattr(AssetRow, "tenant_id")


def test_pending_recovery_enqueue_is_deduplicated_with_expiring_marker():
    class FakeRedis:
        def __init__(self):
            self.keys = set()
            self.entries = []
        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.keys:
                return None
            self.keys.add(key)
            return True
        def xgroup_create(self, *args, **kwargs):
            return True
        def xadd(self, stream, fields):
            self.entries.append((stream, fields))
            return str(len(self.entries))
        def delete(self, key):
            self.keys.discard(key)

    fake = FakeRedis()
    assert redis_queue.enqueue_recovery_once(fake, "job-123") is True
    assert redis_queue.enqueue_recovery_once(fake, "job-123") is False
    assert len(fake.entries) == 1
    assert fake.entries[0][1]["job_id"] == "job-123"
    assert fake.entries[0][1]["job_type"] == "pending-recovery"
    assert redis_queue.recovery_marker_key("job-123") in fake.keys
