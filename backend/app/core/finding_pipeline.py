"""Scanner finding -> correlation -> risk -> alert -> incident pipeline.

Deterministic engines remain the source of truth. Gemini is invoked only after
findings have been normalized, risk-scored and persisted, and its output is
stored as explanatory context; it can never create or delete a finding.
"""
from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from app.core.database import (
    SecurityAlertRow,
    SecurityEventRow,
    IncidentRow,
    session_scope,
    utcnow,
)
from app.core.security_events import create_incident, record_security_event
from app.modules.ai_analysis.analyzer import AIAnalyzer, AIAnalyzerConfigError, AIAnalyzerResponseError


SEV_SCORE = {"Critical": 95, "High": 78, "Medium": 52, "Low": 28, "Info": 8}
CONF_SCORE = {"high": 12, "medium": 6, "low": 0}


def _severity(value: Any, default: str = "Medium") -> str:
    if value is None:
        return default
    s = str(value).replace("_", " ").title()
    return s if s in SEV_SCORE else default


def _finding_id(module: str, target: str, title: str, evidence: str) -> str:
    raw = f"{module}|{target}|{title}|{evidence[:1200]}"
    return "fnd_" + hashlib.sha256(raw.encode()).hexdigest()[:24]


def _risk(severity: str, confidence: str, evidence: str, *, repeated: bool = False) -> int:
    score = SEV_SCORE[severity] + CONF_SCORE.get(confidence, 0)
    text = evidence.lower()
    if any(k in text for k in ("vulnerable", "cve-", "exploit", "injection", "rce", "critical")):
        score += 8
    if repeated:
        score += 10
    return min(100, score)


def _add(out: list[dict], module: str, target: str, title: str, severity: Any,
         evidence: str, description: str, remediation: str,
         affected_asset: str | None = None, confidence: str = "medium") -> None:
    sev = _severity(severity)
    evidence = str(evidence or "")[:4000]
    fid = _finding_id(module, target, title, evidence)
    out.append({
        "finding_id": fid, "source_module": module, "title": title,
        "severity": sev, "confidence": confidence, "description": description,
        "evidence": evidence, "remediation": remediation,
        "affected_asset": affected_asset or target,
    })


def normalize_scan_findings(result: Any) -> list[dict]:
    """Convert scanner-native output to stable, machine-readable findings."""
    data = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    module = data.get("module", "unknown")
    target = data.get("target", "")
    findings: list[dict] = []

    if module == "network":
        for port in data.get("open_ports", []):
            service = " ".join(str(x) for x in [port.get("service_name"), port.get("product"), port.get("version")] if x)
            _add(findings, module, target, f"Open {port.get('protocol','tcp')}/{port.get('port')}",
                 "Low", f"Port state={port.get('state')}; service={service or 'unknown'}",
                 "A network service is reachable from the scanned position.",
                 "Restrict exposure to required sources, harden the service and verify authentication.",
                 f"{port.get('port')}/{port.get('protocol','tcp')}", "high" if port.get("state") == "open" else "medium")
            for script in port.get("scripts", []):
                output = script.get("output", "")
                if output:
                    sev = "High" if any(k in output.lower() for k in ("vulnerable", "cve-", "exploit", "rce")) else "Medium"
                    _add(findings, module, target, f"NSE finding: {script.get('script_id','unknown')}",
                         sev, output, "Nmap NSE produced security-relevant evidence for the exposed service.",
                         "Review the NSE evidence, patch or reconfigure the affected service, and verify with a follow-up scan.",
                         f"{port.get('port')}/{port.get('protocol','tcp')}", "high" if sev == "High" else "medium")
        for script in data.get("host_scripts", []):
            if script.get("output"):
                _add(findings, module, target, f"Host NSE finding: {script.get('script_id','unknown')}",
                     "Medium", script["output"], "Nmap produced host-level security evidence.",
                     "Review the script evidence and remediate the underlying exposure.", target, "medium")

    elif module == "web":
        for check in data.get("vulnerability_checks", []):
            if check.get("vulnerable"):
                _add(findings, module, target, check.get("check_name", "Web vulnerability"),
                     "High" if "sqli" in str(check.get("check_name","")).lower() else "High",
                     check.get("evidence") or "Active check reported vulnerable=True",
                     "A deterministic web security check reported a positive result.",
                     "Validate the finding manually, fix the vulnerable input handling and rerun the scan.",
                     check.get("url") or target, check.get("confidence","medium"))
        for match in data.get("template_findings", []):
            if match.get("matched"):
                _add(findings, module, target, match.get("name") or match.get("template_id","Template finding"),
                     match.get("severity_hint","Medium"), match.get("evidence") or "Template matched",
                     "A deterministic web template matched security-relevant evidence.",
                     "Apply the template remediation and verify the result with a follow-up scan.",
                     match.get("url") or target, "high" if str(match.get("severity_hint","")).lower() in {"high","critical"} else "medium")
        for name in data.get("passive_findings", []):
            _add(findings, module, target, "Passive web security finding", "Medium", name,
                 "Passive response analysis identified a security weakness.",
                 "Review the response configuration and apply the recommended hardening.", target, "medium")
        for name in data.get("cors_findings", []):
            _add(findings, module, target, "CORS security finding", "Medium", name,
                 "CORS analysis identified a potentially unsafe cross-origin configuration.",
                 "Restrict allowed origins and credentials to trusted applications.", target, "medium")
        for header in data.get("security_headers", []):
            if not header.get("present"):
                _add(findings, module, target, f"Missing security header: {header.get('header_name')}",
                     "Low", f"Header {header.get('header_name')} is absent.",
                     "Add the header with a configuration appropriate to the application.",
                     header.get("header_name"), "high")

        api = data.get("api_security") or {}
        if api:
            for match in api.get("template_matches", []):
                _add(findings, "api_security", target, match.get("title") or match.get("template_id","API template"),
                     match.get("severity","Medium"), match.get("evidence",""),
                     "The integrated API engine reported deterministic security evidence.",
                     match.get("remediation","Review and remediate the affected API control."),
                     match.get("endpoint") or target, "high" if str(match.get("severity","")).lower() in {"high","critical"} else "medium")
            for f in api.get("auth_findings", []):
                _add(findings, "api_security", target, "API authentication finding", "Medium", f,
                     "The API security engine identified an authentication-related weakness.",
                     "Review authentication enforcement and verify protected endpoints with explicit test identities.",
                     target, "medium")
            for s in api.get("schema_validations", []):
                if s.get("valid") is False:
                    _add(findings, "api_security", target, "API schema validation failure", "Medium",
                         "; ".join(s.get("errors", [])) or "Schema validation failed",
                         "The observed API response/request did not satisfy the declared schema.",
                         "Correct the API contract or implementation and add regression tests.",
                         s.get("endpoint") or target, "high")

    return findings


async def correlate_and_escalate(*, tenant_id: str, result: Any, job_id: str | None = None,
                                  run_gemini: bool = True) -> dict:
    """Persist findings and create/update alerts/incidents. Returns pipeline metadata."""
    findings = normalize_scan_findings(result)
    target = getattr(result, "target", "") or ""
    scan_id = getattr(result, "scan_id", None)
    now = utcnow()
    pipeline = {"findings": len(findings), "alerts": 0, "incidents": 0, "reused_incidents": 0,
                "gemini": "skipped", "finding_ids": []}

    for finding in findings[:300]:
        # Correlate repeated evidence for the same tenant/target/finding within 24h.
        repeated = False
        with session_scope(tenant_id) as db:
            since = now - timedelta(hours=24)
            repeated = db.scalar(select(SecurityEventRow.event_id).where(
                SecurityEventRow.tenant_id == tenant_id,
                SecurityEventRow.target == target,
                SecurityEventRow.data["finding_id"].as_string() == finding["finding_id"],
                SecurityEventRow.created_at >= since,
            ).limit(1)) is not None

        risk = _risk(finding["severity"], finding["confidence"], finding["evidence"], repeated=repeated)
        finding["risk_score"] = risk
        event = record_security_event(
            tenant_id=tenant_id, event_type="scanner.finding",
            target=target, data={"finding_id": finding["finding_id"], "scan_id": scan_id,
                                  "job_id": job_id, **finding}, auto_alert=risk >= 60)
        pipeline["finding_ids"].append(finding["finding_id"])
        if risk < 70:
            continue

        severity = "critical" if risk >= 90 else "high" if risk >= 70 else "medium"
        title = f"{severity.title()} security finding: {finding['title']}"
        related = {"scan_id": scan_id, "finding_id": finding["finding_id"]}
        evidence = [{"type": "scanner", "module": finding["source_module"],
                     "finding_id": finding["finding_id"], "evidence": finding["evidence"][:4000],
                     "risk_score": risk}]
        # Do not create duplicate open incidents for the same finding.
        existing = None
        with session_scope(tenant_id) as db:
            existing = db.scalar(select(IncidentRow).where(
                IncidentRow.tenant_id == tenant_id,
                IncidentRow.related_finding_id == finding["finding_id"],
                IncidentRow.status.in_(["open", "investigating"]),
            ).limit(1))
        if existing:
            with session_scope(tenant_id) as db:
                row = db.get(IncidentRow, existing.incident_id)
                row.evidence = (row.evidence or [])[-19:] + evidence
                row.timeline = (row.timeline or [])[-19:] + [{"at": now.isoformat(), "event": "finding.reobserved",
                    "scan_id": scan_id, "risk_score": risk}]
                row.updated_at = now
            pipeline["reused_incidents"] += 1
            continue

        iid = create_incident(
            tenant_id=tenant_id, title=title,
            description=f"Deterministic scanner evidence correlated at risk score {risk}/100.",
            severity=severity, related=related, evidence=evidence,
        )
        with session_scope(tenant_id) as db:
            # Link the alert generated by record_security_event to the incident.
            alert = db.scalar(select(SecurityAlertRow).where(
                SecurityAlertRow.tenant_id == tenant_id,
                SecurityAlertRow.event_id == event["event_id"],
            ).order_by(SecurityAlertRow.created_at.desc()).limit(1))
            if alert:
                alert.data = {**(alert.data or {}), "finding_id": finding["finding_id"], "scan_id": scan_id}
                if hasattr(alert, "incident_id"):
                    alert.incident_id = iid
        pipeline["incidents"] += 1

    # Gemini is explanatory only. It receives the scanner result after deterministic persistence.
    if run_gemini and findings:
        try:
            analyzer = AIAnalyzer()
            module = getattr(result, "module", "")
            report = await analyzer.analyze(
                network_result=result if module == "network" else None,
                web_result=result if module == "web" else None,
                api_result=result if module == "api_security" else None,
                language="en",
            )
            explanation = report.executive_summary[:6000]
            if report.findings:
                explanation += "\n\n" + "\n".join(
                    f"- {f.title}: {f.description} Remediation: {f.remediation}"
                    for f in report.findings[:8]
                )
            # Update all incidents produced by this scan; no severity/state changes by Gemini.
            with session_scope(tenant_id) as db:
                rows = db.scalars(select(IncidentRow).where(
                    IncidentRow.tenant_id == tenant_id,
                    IncidentRow.related_scan_id == scan_id,
                    IncidentRow.status.in_(["open", "investigating"]),
                )).all()
                for row in rows:
                    row.ai_explanation = explanation
                    row.timeline = (row.timeline or [])[-19:] + [{"at": utcnow().isoformat(),
                        "event": "gemini.explanation_added", "model": report.model_used,
                        "note": "explanatory only; deterministic finding remains authoritative"}]
                    row.updated_at = utcnow()
            pipeline["gemini"] = "completed"
        except AIAnalyzerConfigError:
            pipeline["gemini"] = "not_configured"
        except AIAnalyzerResponseError:
            pipeline["gemini"] = "failed"
        except Exception:
            pipeline["gemini"] = "failed"

    return pipeline


def _surface_risk(change: dict) -> tuple[str, int]:
    field=change.get("field","")
    added=change.get("added",[]) or []
    if field in {"tls_not_after","tls_expiry_days"}:
        return "high", 78
    if field in {"ports","services"} and added:
        return "high", 72
    if field in {"ips","dns_records","apis","endpoints"} and added:
        return "medium", 64
    if field == "technologies" and added:
        return "low", 35
    return "low", 30


def correlate_surface_changes(*, tenant_id: str, result: Any, changes: list[dict], run_gemini: bool = True) -> dict:
    """Turn deterministic attack-surface deltas into the same finding/event/alert/incident contract."""
    target=getattr(result,"target","") or ""
    scan_id=getattr(result,"scan_id",None)
    out={"findings":0,"alerts":0,"incidents":0,"reused_incidents":0,"gemini":"skipped","finding_ids":[]}
    for change in changes[:200]:
        field=change.get("field","surface")
        added=change.get("added",[]) or []
        removed=change.get("removed",[]) or []
        if not added and not removed: continue
        severity, risk=_surface_risk(change)
        title=f"Attack surface changed: {field}"
        evidence=f"Added={added[:30]}; Removed={removed[:30]}"
        fid=_finding_id("attack_surface",target,title,evidence)
        finding={"finding_id":fid,"source_module":"attack_surface","title":title,"severity":severity.title(),"confidence":"high","description":f"Continuous monitoring detected a deterministic change in {field}.","evidence":evidence,"remediation":"Validate the change against the approved asset inventory; restrict unexpected exposure and rerun monitoring.","affected_asset":target,"risk_score":risk,"change":change}
        repeated=False
        with session_scope(tenant_id) as db:
            repeated=db.scalar(select(SecurityEventRow.event_id).where(SecurityEventRow.tenant_id==tenant_id,SecurityEventRow.target==target,SecurityEventRow.event_type=="attack_surface.change",SecurityEventRow.data["finding_id"].as_string()==fid,SecurityEventRow.created_at>=utcnow()-timedelta(hours=24)).limit(1)) is not None
        if repeated: risk=min(100,risk+10); finding["risk_score"]=risk
        event=record_security_event(tenant_id=tenant_id,event_type="attack_surface.change",target=target,data={"scan_id":scan_id,**finding},auto_alert=(risk>=60 and not repeated))
        out["findings"]+=1; out["finding_ids"].append(fid)
        if risk>=60 and not repeated: out["alerts"]+=1
        if risk<70: continue
        with session_scope(tenant_id) as db:
            existing=db.scalar(select(IncidentRow).where(IncidentRow.tenant_id==tenant_id,IncidentRow.related_finding_id==fid,IncidentRow.status.in_(["open","investigating"])).limit(1))
        if existing:
            out["reused_incidents"]+=1
            continue
        iid=create_incident(tenant_id=tenant_id,title=title,description=f"Continuous attack-surface monitoring detected a {field} change.",severity="critical" if risk>=90 else "high",related={"scan_id":scan_id,"finding_id":fid},evidence=[{"type":"attack_surface","change":change,"risk_score":risk}])
        with session_scope(tenant_id) as db:
            alert=db.scalar(select(SecurityAlertRow).where(SecurityAlertRow.tenant_id==tenant_id,SecurityAlertRow.event_id==event["event_id"]).order_by(SecurityAlertRow.created_at.desc()).limit(1))
            if alert: alert.incident_id=iid
        out["incidents"]+=1
    return out
