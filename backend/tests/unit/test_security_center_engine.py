from sqlalchemy import select
from app.core.database import session_scope, SecurityAlertRow, SecurityEventRow, IncidentRow
from app.core.security_events import record_security_event, create_incident


async def test_privileged_event_creates_critical_alert():
    tid = "test-security-engine-priv"
    result = await record_security_event(
        tenant_id=tid,
        event_type="admin.api_key.created",
        actor_user_id="u1",
        target="key1",
        data={"scopes": ["admin:*"]},
    )
    assert result["severity"] == "critical"
    async with session_scope(tid) as db:
        assert (await db.get(SecurityEventRow, result["event_id"])) is not None
        alert = (await db.scalars(select(SecurityAlertRow).where(SecurityAlertRow.tenant_id == tid))).one()
        assert alert.severity == "critical"
        assert alert.status == "open"


async def test_repeated_login_failures_escalate():
    tid = "test-security-engine-login"
    for _ in range(5):
        await record_security_event(tenant_id=tid, event_type="auth.login_failed", data={"identifier": "a@example.com"})
    async with session_scope(tid) as db:
        events = (await db.scalars(select(SecurityEventRow).where(SecurityEventRow.tenant_id == tid).order_by(SecurityEventRow.created_at))).all()
        assert events[-1].event_type == "auth.suspicious_login"
        assert events[-1].risk_score >= 70


async def test_incident_creation_persists_timeline():
    tid = "test-security-engine-incident"
    iid = await create_incident(tenant_id=tid, title="Test incident", severity="high", evidence=[{"source": "test"}])
    async with session_scope(tid) as db:
        incident = await db.get(IncidentRow, iid)
        assert incident is not None
        assert incident.status == "open"
        assert incident.timeline
        assert incident.evidence[0]["source"] == "test"
