"""Deterministic security event -> detection -> risk -> alert engine."""
from __future__ import annotations
import secrets
from datetime import timedelta
from sqlalchemy import select, func
from app.core.database import SecurityEventRow, SecurityAlertRow, IncidentRow, AuditLogRow, session_scope, utcnow

SEVERITY_RANK={"low":20,"medium":40,"high":70,"critical":95}
RULES={
    "auth.login_failed": ("medium", 45, "Repeated authentication failure"),
    "auth.suspicious_login": ("high", 75, "Suspicious login activity"),
    "admin.api_key.created": ("critical", 95, "Privileged API key created"),
    "admin.user.role_changed": ("critical", 90, "Privileged role changed"),
    "admin.user.disabled": ("high", 75, "Administrator changed account state"),
    "admin.policy.changed": ("high", 75, "Security policy changed"),
    "admin.session.revoked_all": ("medium", 55, "Mass session revocation"),
    "security.mfa_step_up_failed": ("high", 80, "Sensitive action MFA verification failed"),
    "security.mfa_required": ("medium", 50, "MFA is required for privileged access"),
    "scanner.finding": ("medium", 60, "Deterministic scanner finding"),
}
def _severity(score:int)->str:
    return "critical" if score>=90 else "high" if score>=70 else "medium" if score>=40 else "low"

async def record_security_event(*, tenant_id:str, event_type:str, actor_user_id:str|None=None,
                          target:str|None=None, data:dict|None=None, auto_alert:bool=True,
                          idempotency_key:str|None=None):
    data=dict(data or {})
    if idempotency_key:
        # Persist the key inside the event payload so retries can find the original
        # event without a schema migration. This is sequential idempotency; a DB
        # uniqueness constraint is still required for cross-worker race-proofing.
        data["_idempotency_key"] = str(idempotency_key)[:240]
        async with session_scope(tenant_id) as db:
            existing = await db.scalar(select(SecurityEventRow).where(
                SecurityEventRow.tenant_id == tenant_id,
                SecurityEventRow.event_type == event_type,
                SecurityEventRow.target == target,
                SecurityEventRow.data["_idempotency_key"].as_string() == str(idempotency_key)[:240],
            ).order_by(SecurityEventRow.created_at.desc()).limit(1))
            if existing is not None:
                alert = await db.scalar(select(SecurityAlertRow).where(
                    SecurityAlertRow.tenant_id == tenant_id,
                    SecurityAlertRow.event_id == existing.event_id,
                ).limit(1))
                return {"event_id": existing.event_id, "severity": existing.severity,
                        "risk_score": existing.risk_score, "created": False,
                        "alert_created": False, "alert_id": alert.alert_id if alert else None}
    base_sev, score, title=RULES.get(event_type,("low",10,event_type.replace("."," ").title()))
    # Scanner findings carry their deterministic risk score into the event/alert layer.
    if event_type == "scanner.finding":
        supplied = int(data.get("risk_score", score) or score)
        score = max(0, min(100, supplied))
        base_sev = _severity(score)
        title = str(data.get("title") or title)
    # Deterministic correlation: repeated auth failures in a 10-minute window escalate.
    if event_type=="auth.login_failed":
        async with session_scope(tenant_id) as db:
            since=utcnow()-timedelta(minutes=10)
            n=await db.scalar(select(func.count()).select_from(SecurityEventRow).where(
                SecurityEventRow.tenant_id==tenant_id,
                SecurityEventRow.event_type=="auth.login_failed",
                SecurityEventRow.created_at>=since,
                SecurityEventRow.data["identifier"].as_string()==str(data.get("identifier",""))
            )) or 0
            if n>=4:
                event_type="auth.suspicious_login"; base_sev,score,title=RULES[event_type]
    eid=secrets.token_hex(16)
    async with session_scope(tenant_id) as db:
        db.add(SecurityEventRow(event_id=eid,tenant_id=tenant_id,event_type=event_type,severity=base_sev,
                                actor_user_id=actor_user_id,target=target,data=data,risk_score=score,detected=auto_alert,created_at=utcnow()))
        if auto_alert and score>=70:
            aid=secrets.token_hex(16)
            db.add(SecurityAlertRow(alert_id=aid,tenant_id=tenant_id,event_id=eid,title=title,severity=base_sev,
                                    status="open",risk_score=score,data={"event_type":event_type,**data},created_at=utcnow()))
        db.add(AuditLogRow(id=secrets.token_hex(16),tenant_id=tenant_id,event=f"security.event.{event_type}",
                           target=target,data={"event_id":eid,"risk_score":score,**data},created_at=utcnow()))
    return {"event_id":eid,"severity":base_sev,"risk_score":score,"created":True,
            "alert_created":bool(auto_alert and score>=70),"alert_id":aid if auto_alert and score>=70 else None}

async def create_incident(*,tenant_id:str,title:str,description:str="",severity:str="high",
                    assignee_user_id:str|None=None,sla_due_at=None,related:dict|None=None,evidence:list|None=None):
    iid=secrets.token_hex(16); now=utcnow()
    related=related or {}; evidence=evidence or []
    timeline=[{"at":now.isoformat(),"event":"incident.created"}]
    async with session_scope(tenant_id) as db:
        db.add(IncidentRow(incident_id=iid,tenant_id=tenant_id,title=title,description=description,
            severity=severity,status="open",assignee_user_id=assignee_user_id,sla_due_at=sla_due_at,
            related_asset_id=related.get("asset_id"),related_scan_id=related.get("scan_id"),
            related_finding_id=related.get("finding_id"),related_user_id=related.get("user_id"),
            evidence=evidence,timeline=timeline,created_at=now,updated_at=now))
    return iid
