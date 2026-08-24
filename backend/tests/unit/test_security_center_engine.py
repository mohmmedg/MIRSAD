from app.core.database import session_scope, SecurityAlertRow, SecurityEventRow, IncidentRow
from app.core.security_events import record_security_event, create_incident


def test_privileged_event_creates_critical_alert():
    tid = "test-security-engine-priv"
    result = record_security_event(
        tenant_id=tid,
        event_type="admin.api_key.created",
        actor_user_id="u1",
        target="key1",
        data={"scopes": ["admin:*"]},
    )
    assert result["severity"] == "critical"
    with session_scope(tid) as db:
        assert db.get(SecurityEventRow, result["event_id"]) is not None
        alert = db.query(SecurityAlertRow).filter(SecurityAlertRow.tenant_id == tid).one()
        assert alert.severity == "critical"
        assert alert.status == "open"


def test_repeated_login_failures_escalate():
    tid = "test-security-engine-login"
    for _ in range(5):
        record_security_event(tenant_id=tid, event_type="auth.login_failed", data={"identifier": "a@example.com"})
    with session_scope(tid) as db:
        events = list(db.query(SecurityEventRow).filter(SecurityEventRow.tenant_id == tid).order_by(SecurityEventRow.created_at))
        assert events[-1].event_type == "auth.suspicious_login"
        assert events[-1].risk_score >= 70


def test_incident_creation_persists_timeline():
    tid = "test-security-engine-incident"
    iid = create_incident(tenant_id=tid, title="Test incident", severity="high", evidence=[{"source": "test"}])
    with session_scope(tid) as db:
        incident = db.get(IncidentRow, iid)
        assert incident is not None
        assert incident.status == "open"
        assert incident.timeline
        assert incident.evidence[0]["source"] == "test"
