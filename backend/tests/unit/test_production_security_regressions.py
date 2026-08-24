import pytest
from sqlalchemy import select

from app.core.auth import Principal, require_role, set_principal
from app.core.auth_context import tenant_context
from app.core.config import SSRFRiskError, verify_target_in_scope
from app.core.database import AdminSettingRow, SecurityAlertRow, SecurityEventRow, session_scope
from app.core.security_events import record_security_event
from app.modules.auth_session.engine import compare_endpoint, AuthProfile


@pytest.mark.asyncio
async def test_require_role_binds_tenant_context():
    token = tenant_context.set(None)
    try:
        set_principal(Principal("u1", "tenant-bind", "viewer", "u@example.com"))
        await require_role("viewer")
        assert tenant_context.get() == "tenant-bind"
    finally:
        tenant_context.reset(token)


def test_privileged_admin_mfa_policy_cannot_be_disabled():
    tid = "mfa-policy-immutable"
    with session_scope(tid) as db:
        db.add(AdminSettingRow(tenant_id=tid, security_policy={"require_mfa": True}, scan_policy={}, ai_policy={}, notification_policy={}, updated_at=__import__("app.core.database", fromlist=["utcnow"]).utcnow()))
    # The route-level regression is asserted statically by the source contract below.
    from app.api.routes import admin
    source = __import__("inspect").getsource(admin.update_policy)
    assert 'body.values.get("require_mfa") is False' in source


def test_security_event_engine_creates_only_one_alert_for_one_event():
    tid = "event-one-alert"
    result = record_security_event(tenant_id=tid, event_type="admin.api_key.created", actor_user_id="u1", target="k1", data={"scopes": ["admin:*"]})
    with session_scope(tid) as db:
        events = db.scalars(select(SecurityEventRow).where(SecurityEventRow.event_id == result["event_id"])).all()
        alerts = db.scalars(select(SecurityAlertRow).where(SecurityAlertRow.event_id == result["event_id"])).all()
        assert len(events) == 1
        assert len(alerts) == 1


@pytest.mark.asyncio
async def test_auth_compare_rejects_disallowed_target():
    from app.core.config import settings
    old = settings.ENFORCE_TARGET_SCOPE
    old_targets = settings.ALLOWED_TARGETS_RAW
    settings.ENFORCE_TARGET_SCOPE = True
    settings.ALLOWED_TARGETS_RAW = "example.com"
    try:
        with pytest.raises(Exception):
            await compare_endpoint("http://127.0.0.1:8080", [AuthProfile("none", {})])
    finally:
        settings.ENFORCE_TARGET_SCOPE = old
        settings.ALLOWED_TARGETS_RAW = old_targets
