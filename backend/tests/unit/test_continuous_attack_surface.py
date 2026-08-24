from app.core.auth_context import tenant_context
from app.core.database import init_db, session_scope, ContinuousScheduleRow
from app.modules.asset_inventory.inventory import inventory

def test_asset_surface_baseline_then_detects_changes():
    token=tenant_context.set('asm-test'); init_db()
    try:
        first=inventory.upsert('example.com',snapshot={'ips':['1.1.1.1'],'ports':['443/tcp'],'technologies':['nginx'],'dns_records':['1.1.1.1'],'tls_protocol':['TLSv1.3'],'tls_not_after':'Jan 01 00:00:00 2030 GMT'})
        assert first['surface_changes']==[]
        second=inventory.upsert('example.com',snapshot={'ips':['1.1.1.1','2.2.2.2'],'ports':['443/tcp','8443/tcp'],'technologies':['nginx','node'],'dns_records':['1.1.1.1','2.2.2.2'],'tls_protocol':['TLSv1.2'],'tls_not_after':'Jan 01 00:00:00 2027 GMT'})
        fields={c['field'] for c in second['surface_changes']}
        assert {'ips','ports','technologies','dns_records','tls_protocol','tls_not_after'} <= fields
    finally: tenant_context.reset(token)

def test_continuous_schedule_is_tenant_scoped():
    token=tenant_context.set('tenant-a'); init_db()
    try:
        with session_scope('tenant-a') as db: db.add(ContinuousScheduleRow(schedule_id='s-a',tenant_id='tenant-a',target='a.example',request={'target':'a.example'},interval_seconds=300,enabled=True))
        token2=tenant_context.set('tenant-b')
        try:
            with session_scope('tenant-b') as db: assert db.query(ContinuousScheduleRow).filter(ContinuousScheduleRow.schedule_id=='s-a', ContinuousScheduleRow.tenant_id=='tenant-b').first() is None
        finally: tenant_context.reset(token2)
    finally: tenant_context.reset(token)


class _FakeRedis:
    def __init__(self):
        self.values = {}
        self.queue = []
    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True
    def rpush(self, queue, payload):
        self.queue.append((queue, payload))


def test_scheduler_is_durable_and_replica_safe():
    import json
    from datetime import datetime, timezone, timedelta
    from app.modules.continuous import ContinuousScanner, CONTINUOUS_QUEUE, ENQUEUE_LOCK_PREFIX

    token = tenant_context.set('durable-a'); init_db()
    try:
        with session_scope('durable-a') as db:
            db.query(ContinuousScheduleRow).delete()
            db.add(ContinuousScheduleRow(
                schedule_id='durable-1', tenant_id='durable-a', target='a.example',
                request={'target':'a.example'}, interval_seconds=300, enabled=True,
                next_run_at=datetime.now(timezone.utc) - timedelta(seconds=1)
            ))
        r = _FakeRedis()
        assert ContinuousScanner.enqueue_due(r, 'replica-1') == 1
        assert len(r.queue) == 1
        assert r.queue[0][0] == CONTINUOUS_QUEUE
        assert json.loads(r.queue[0][1])['schedule_id'] == 'durable-1'
        # A second replica cannot enqueue the same schedule while the
        # short-lived distributed lock is held.
        assert ContinuousScanner.enqueue_due(r, 'replica-2') == 0
        with session_scope('durable-a') as db:
            row = db.get(ContinuousScheduleRow, 'durable-1')
            assert row.next_run_at is not None
            assert row.last_status == 'queued'
    finally:
        tenant_context.reset(token)
