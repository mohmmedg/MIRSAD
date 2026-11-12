"""Scanner finding -> correlation -> risk -> alert -> incident pipeline.

Deterministic engines remain the source of truth. Gemini is invoked only after
findings have been normalized, risk-scored and persisted, and its output is
stored as explanatory context; it can never create or delete a finding.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select

logger = logging.getLogger(__name__)

from app.core.database import (
    SecurityAlertRow,
    SecurityEventRow,
    VerificationAttemptRow,
    IncidentRow,
    session_scope,
    utcnow,
)
from app.core.security_events import create_incident, record_security_event
from app.modules.ai_analysis.analyzer import AIAnalyzer, AIAnalyzerConfigError, AIAnalyzerResponseError
from app.modules.normalizer.normalizer import verify_findings, verify_findings_live
from app.modules.correlator.correlator import correlate
from app.core.finding_confirmation import apply_confirmation_gate
from app.schemas.platform import NormalizedFinding, FindingEvidence


SEV_SCORE = {"Critical": 95, "High": 78, "Medium": 52, "Low": 28, "Info": 8}
CONF_SCORE = {"high": 12, "medium": 6, "low": 0}


def _severity(value: Any, default: str = "Medium") -> str:
    if value is None:
        return default
    s = str(value).replace("_", " ").title()
    return s if s in SEV_SCORE else default


def _finding_id(module: str, target: str, title: str, evidence: str, *, method: str = "", parameter: str = "", rule: str = "", location: str = "") -> str:
    raw = "|".join([str(module).lower(),str(target).lower(),str(method).upper(),str(parameter).lower(),str(rule or title).lower(),str(location).lower()])
    return "fnd_" + hashlib.sha256(raw.encode()).hexdigest()[:32]


def _risk(severity: str, confidence: str, evidence: str, *, repeated: bool = False) -> int:
    score = SEV_SCORE[severity] + CONF_SCORE.get(confidence, 0)
    text = evidence.lower()
    if any(k in text for k in ("vulnerable", "cve-", "exploit", "injection", "rce", "critical")):
        score += 8
    if repeated:
        score += 10
    return min(100, score)


def _verification_record(finding: dict) -> dict:
    """Return only verification facts actually produced by the verifier.

    Scanner observations may remain DETECTED/UNVERIFIED without a verification
    method or timestamp; never synthesize either as if a live check occurred.
    """
    return {
        "verification_id": finding.get("verification_id"),
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "method": finding.get("verification_method"),
        "result": str(finding.get("verification_status") or "UNVERIFIED").upper(),
        "timestamp": finding.get("verification_timestamp"),
    }


def _add(out: list[dict], module: str, target: str, title: str, severity: Any,
         evidence: str, description: str, remediation: str,
         affected_asset: str | None = None, confidence: str = "medium",
         risk_context: dict[str, float] | None = None,
         verification_status: str = "DETECTED", method: str = "",
         parameter: str = "", rule: str = "", location: str = "") -> None:
    sev = _severity(severity)
    # A scanner-native result is an observation, not an independent verification.
    # The secondary SOC path must not trust a VERIFIED flag emitted by a scanner
    # result object. Only a finding carrying an explicit verification method may
    # enter this path as VERIFIED; the authoritative live verifier is responsible
    # for producing that method/evidence in the canonical assessment pipeline.
    verification_status = str(verification_status or "DETECTED").upper()
    if verification_status == "VERIFIED" and not method:
        verification_status = "DETECTED"
    if verification_status not in {"VERIFIED", "DETECTED", "UNVERIFIED", "FALSE_POSITIVE", "NOT_APPLICABLE", "REJECTED"}:
        verification_status = "DETECTED"
    # Canonical storage keeps the complete evidence. UI/export presentation may
    # truncate separately, but the forensic record must not be shortened here.
    evidence = str(evidence or "")
    # Every scanner-native observation receives a stable rule identity before
    # entering the canonical normalizer. This is required for live verification
    # and the shared correlator to behave identically across scan entry points.
    if not rule:
        if title.startswith("Missing security header: "):
            rule = "WEB-HEADER-CONFIG-" + title.split(": ", 1)[1].replace("-", "_").upper()
        elif title == "CORS security finding":
            rule = "WEB-CORS-CONFIG"
        elif title == "Passive web security finding":
            rule = "WEB-PASSIVE-FINDING"
        else:
            slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:80]
            rule = f"{module.upper()}-{slug}"
    fid = _finding_id(module, affected_asset or target, title, evidence,
                      method=method, parameter=parameter, rule=rule, location=location)
    out.append({
        "finding_id": fid, "source_module": module, "title": title,
        "rule_id": rule, "method": method or None, "parameter": parameter or None,
        "location": location or None, "severity": sev, "confidence": confidence, "description": description,
        "evidence": evidence, "remediation": remediation,
        "affected_asset": affected_asset or target, "verification_status": verification_status,
        "verification_method": method or None, "verification_reason": None,
        "cwe": None, "mitre_attack": [], "cve_matches": [], "risk_context": risk_context or {},
    })


def _contextual_header_severity(name: str, data: dict) -> tuple[str, dict[str, float]]:
    html = "html" in str(data.get("content_type", "")).lower()
    endpoints = int(data.get("endpoints_count", 0) or 0)
    has_auth = bool(data.get("auth_present")) or bool(data.get("cookie_checks"))
    if name == "Content-Security-Policy":
        return (("Medium" if html and endpoints else "Low"), {"exploitability": 0.5 if html and endpoints else 0.35, "exposure": 0.8 if html else 0.5, "asset_criticality": 0.75 if has_auth else 0.4})
    if name == "Strict-Transport-Security":
        return (("Medium" if has_auth else "Low"), {"exploitability": 0.3, "exposure": 0.9 if has_auth else 0.6, "asset_criticality": 0.8 if has_auth else 0.4})
    return ("Low", {"exploitability": 0.3, "exposure": 0.6 if html else 0.4, "asset_criticality": 0.7 if has_auth else 0.4})

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
                     check.get("url") or target, check.get("confidence","medium"), None, "DETECTED")
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
        cors = data.get("cors_verification") or {}
        for name in data.get("cors_findings", []):
            verified = cors.get("status") == "VERIFIED_RISK"
            sensitive = bool(cors.get("sensitive_response"))
            sev = "High" if verified and sensitive else ("Medium" if verified else "Info")
            ctx = {"exploitability": 0.85 if verified and sensitive else (0.55 if verified else 0.1), "exposure": 0.95 if verified else 0.4, "asset_criticality": 0.9 if verified and sensitive else 0.45}
            _add(findings, module, target, "CORS security finding", sev, name,
                 "CORS is an observation unless browser-readable exposure is verified; wildcard alone is not a Medium finding.",
                 "Restrict allowed origins and credentials to trusted applications.", target, "high" if verified else "medium", ctx, "DETECTED")
        for header in data.get("security_headers", []):
            if not header.get("present"):
                hname = header.get("header_name") or "unknown"
                sev, ctx = _contextual_header_severity(hname, data)
                _add(findings, module, target, f"Missing security header: {hname}",
                     sev, f"Header {hname} is absent; severity is contextual and not a standalone vulnerability.",
                     "The response confirms that this security control is absent.",
                     "Add the header with a configuration appropriate to the application.",
                     target, "high", ctx, "DETECTED")

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

    from app.modules.threat_intel.enrichment import enrich_finding_dict
    for f in findings:
        enrich_finding_dict(f)

    return findings


def _scanner_findings_to_canonical(findings: list[dict], *, scan_id: str | None) -> list[NormalizedFinding]:
    """Convert legacy scanner dictionaries into the one canonical finding model."""
    confidence_map = {"low": 0.4, "medium": 0.7, "high": 0.9, "critical": 0.95}
    canonical: list[NormalizedFinding] = []
    for item in findings:
        raw_conf = item.get("confidence", "medium")
        if isinstance(raw_conf, (int, float)):
            conf = float(raw_conf)
        else:
            conf = confidence_map.get(str(raw_conf).lower(), 0.7)
        evidence_text = str(item.get("evidence") or "")
        canonical.append(NormalizedFinding(
            finding_id=str(item["finding_id"]), scan_id=scan_id,
            source_module=str(item.get("source_module") or "unknown"),
            rule_id=str(item.get("rule_id") or item.get("title") or "UNKNOWN"),
            title=str(item.get("title") or "Security finding"),
            severity=str(item.get("severity") or "Info"), confidence=conf,
            scanner_confidence=conf, verification_status=str(item.get("verification_status") or "DETECTED"),
            method=item.get("method"), parameter=item.get("parameter"), location=item.get("location"),
            description=str(item.get("description") or ""), affected_asset=item.get("affected_asset"),
            remediation=str(item.get("remediation") or ""), risk_context=item.get("risk_context") or {},
            cve_matches=item.get("cve_matches") or [], mitre_attack=item.get("mitre_attack") or [],
            cwe=item.get("cwe"), evidence=[FindingEvidence(
                evidence_id=f"obs-{item['finding_id']}", source=str(item.get("source_module") or "unknown"),
                asset=str(item.get("affected_asset") or ""), evidence=evidence_text, confidence=conf,
            )] if evidence_text else [],
        ))
    return canonical


async def _canonicalize_scanner_findings(*, result: Any, tenant_id: str, scan_id: str | None, job_id: str | None) -> tuple[list[dict], dict]:
    """Single scanner path: Observation → Evidence → Rule → Normalize → Dedup → Verify → Finding/Risk."""
    observed = normalize_scan_findings(result)
    data_for_cve = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    if data_for_cve.get("module") == "network":
        from app.modules.threat_intel.cve_matcher import attach_cve_matches_dicts
        try:
            await attach_cve_matches_dicts(observed, data_for_cve.get("open_ports", []))
        except Exception:
            logger.warning("CVE match enrichment failed for scan %s", scan_id, exc_info=True)
    canonical = _scanner_findings_to_canonical(observed, scan_id=scan_id)
    # Live verification is the only path allowed to promote DETECTED/UNVERIFIED
    # observations. Scanner output alone never becomes VERIFIED.
    verification = await verify_findings_live(canonical, scan_id=scan_id, tenant_id=tenant_id, job_id=job_id)
    verification["confirmation"] = apply_confirmation_gate(canonical)
    correlated = correlate(canonical)
    return [f.model_dump(mode="json") for f in correlated], verification


async def correlate_and_escalate(*, tenant_id: str, result: Any, job_id: str | None = None,
                                  run_gemini: bool = True) -> dict:
    """Canonical scanner pipeline followed by deterministic SOC persistence."""
    target = getattr(result, "target", "") or ""
    scan_id = getattr(result, "scan_id", None) or job_id
    findings, verification_summary = await _canonicalize_scanner_findings(
        result=result, tenant_id=tenant_id, scan_id=scan_id, job_id=job_id
    )
    now = utcnow()
    verification_counts = {k: sum(1 for f in findings if f.get("verification_status") == k) for k in ("VERIFIED", "DETECTED", "UNVERIFIED", "REJECTED")}
    pipeline = {"findings": len(findings), "alerts": 0, "incidents": 0, "reused_incidents": 0,
                "gemini": "skipped", "finding_ids": [],
                "verification": {**verification_counts, **{k: verification_summary.get(k, verification_counts.get(k, 0)) for k in ("verified","detected","unverified","false_positive","not_applicable","rejected")}, "all_findings_verified": verification_summary.get("all_findings_verified", False)}, "verification_records": []}

    # Batch the two read-only lookups that used to run once per finding inside
    # the loop below (up to 300 findings x 2 queries = 600 individual DB round
    # trips per scan). Semantics are unchanged: the loop below still checks the
    # exact same conditions, just against these pre-fetched sets instead of a
    # fresh query per iteration.
    capped_findings = findings  # no finding-retention cap; 300 was an optimization bound that silently skipped verification IDs
    since = now - timedelta(hours=24)
    async with session_scope(tenant_id) as db:
        repeated_finding_ids: set[str] = {
            row[0] for row in (await db.execute(
                select(SecurityEventRow.data["finding_id"].as_string()).where(
                    SecurityEventRow.tenant_id == tenant_id,
                    SecurityEventRow.target == target,
                    SecurityEventRow.created_at >= since,
                )
            )).all()
        }
    for finding in capped_findings:
        # Correlate repeated evidence for the same tenant/target/finding within 24h.
        repeated = finding["finding_id"] in repeated_finding_ids

        # Verification is produced only by the canonical live verifier. Never
        # synthesize a verification attempt merely because a scanner emitted data.
        verification_result = str(finding.get("verification_status") or "UNVERIFIED").upper()
        # An ID identifies this pipeline record, not proof that verification ran.
        # Method/timestamp remain null unless the canonical verifier supplied them.
        verification_id = finding.get("verification_id") or ("ver_" + hashlib.sha256(
            f"{tenant_id}:{finding['finding_id']}:{scan_id or job_id or now.isoformat()}".encode()
        ).hexdigest()[:32])
        finding["verification_id"] = verification_id
        pipeline["verification_records"].append(_verification_record(finding))
        risk_obj = finding.get("risk") or {}
        risk = int(round(float(risk_obj.get("score", 0)))) if isinstance(risk_obj, dict) else int(finding.get("risk_contribution") or 0)
        if repeated:
            risk = min(100, risk + 10)
        finding["risk_score"] = risk
        event = await record_security_event(
            tenant_id=tenant_id, event_type="scanner.finding",
            target=target, data={"finding_id": finding["finding_id"], "scan_id": scan_id,
                                  "job_id": job_id, **finding}, auto_alert=risk >= 60,
            idempotency_key=(f"scanner.finding:{scan_id}:{finding['finding_id']}" if scan_id else None))
        # record_security_event creates an alert only at score >= 70. Keep the
        # returned pipeline summary consistent with the persisted alert row.
        if event.get("created") and event.get("alert_created"):
            pipeline["alerts"] += 1
        pipeline["finding_ids"].append(finding["finding_id"])
        if risk < 70:
            continue

        severity = "critical" if risk >= 90 else "high" if risk >= 70 else "medium"
        title = f"{severity.title()} security finding: {finding['title']}"
        related = {"scan_id": scan_id, "finding_id": finding["finding_id"]}
        evidence = [{"type": "scanner", "module": finding["source_module"],
                     "finding_id": finding["finding_id"], "evidence": finding["evidence"],
                     "risk_score": risk}]
        # Do not create duplicate open incidents for the same finding.
        existing = None
        async with session_scope(tenant_id) as db:
            existing = await db.scalar(select(IncidentRow).where(
                IncidentRow.tenant_id == tenant_id,
                IncidentRow.related_finding_id == finding["finding_id"],
                IncidentRow.status.in_(["open", "investigating"]),
            ).limit(1))
        if existing:
            async with session_scope(tenant_id) as db:
                row = await db.get(IncidentRow, existing.incident_id)
                if row is None:
                    continue
                row.evidence = (row.evidence or [])[-19:] + evidence
                row.timeline = (row.timeline or [])[-19:] + [{"at": now.isoformat(), "event": "finding.reobserved",
                    "scan_id": scan_id, "risk_score": risk}]
                row.updated_at = now
            pipeline["reused_incidents"] += 1
            continue

        iid = await create_incident(
            tenant_id=tenant_id, title=title,
            description=f"Deterministic scanner evidence correlated at risk score {risk}/100.",
            severity=severity, related=related, evidence=evidence,
        )
        async with session_scope(tenant_id) as db:
            # Link the alert generated by record_security_event to the incident.
            alert = await db.scalar(select(SecurityAlertRow).where(
                SecurityAlertRow.tenant_id == tenant_id,
                SecurityAlertRow.event_id == event["event_id"],
            ).order_by(SecurityAlertRow.created_at.desc()).limit(1))
            if alert:
                alert.data = {**(alert.data or {}), "finding_id": finding["finding_id"], "scan_id": scan_id}
                if hasattr(alert, "incident_id"):
                    alert.incident_id = iid
        pipeline["incidents"] += 1

    try:
        if hasattr(result, "pipeline"):
            result.pipeline = {**(getattr(result, "pipeline", {}) or {}), **pipeline}
    except Exception:
        logger.debug("Failed to attach pipeline summary onto scan result object", exc_info=True)

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
            async with session_scope(tenant_id) as db:
                rows = (await db.scalars(select(IncidentRow).where(
                    IncidentRow.tenant_id == tenant_id,
                    IncidentRow.related_scan_id == scan_id,
                    IncidentRow.status.in_(["open", "investigating"]),
                ))).all()
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


async def correlate_surface_changes(*, tenant_id: str, result: Any, changes: list[dict], run_gemini: bool = True) -> dict:
    """Turn deterministic attack-surface deltas into the same finding/event/alert/incident contract."""
    target=getattr(result,"target","") or ""
    scan_id=getattr(result,"scan_id",None)
    out={"findings":0,"alerts":0,"incidents":0,"reused_incidents":0,"gemini":"skipped","finding_ids":[]}
    capped_changes = changes[:200]
    # Same batching technique as correlate_and_escalate() above: this "repeated
    # in the last 24h" check used to run once per change (up to 200 individual
    # DB round trips per continuous-monitoring pass). It's unconditional (runs
    # for every change, unlike the incident lookup below which only runs when
    # risk>=70), so it dominates the round-trip count and is safe to batch —
    # it's read-only and doesn't affect the conditional incident logic.
    since = utcnow() - timedelta(hours=24)
    async with session_scope(tenant_id) as db:
        repeated_finding_ids: set[str] = {
            row[0] for row in (await db.execute(
                select(SecurityEventRow.data["finding_id"].as_string()).where(
                    SecurityEventRow.tenant_id == tenant_id,
                    SecurityEventRow.target == target,
                    SecurityEventRow.event_type == "attack_surface.change",
                    SecurityEventRow.created_at >= since,
                )
            )).all()
        }
    for change in capped_changes:
        field=change.get("field","surface")
        added=change.get("added",[]) or []
        removed=change.get("removed",[]) or []
        if not added and not removed: continue
        severity, risk=_surface_risk(change)
        title=f"Attack surface changed: {field}"
        evidence=f"Added={added[:30]}; Removed={removed[:30]}"
        fid=_finding_id("attack_surface",target,title,evidence)
        finding={"finding_id":fid,"source_module":"attack_surface","title":title,"severity":severity.title(),"confidence":"high","description":f"Continuous monitoring detected a deterministic change in {field}.","evidence":evidence,"remediation":"Validate the change against the approved asset inventory; restrict unexpected exposure and rerun monitoring.","affected_asset":target,"risk_score":risk,"change":change}
        repeated = fid in repeated_finding_ids
        if repeated: risk=min(100,risk+10); finding["risk_score"]=risk
        event=await record_security_event(tenant_id=tenant_id,event_type="attack_surface.change",target=target,data={"scan_id":scan_id,**finding},auto_alert=(risk>=60 and not repeated))
        out["findings"]+=1; out["finding_ids"].append(fid)
        if risk>=60 and not repeated: out["alerts"]+=1
        if risk<70: continue
        async with session_scope(tenant_id) as db:
            existing=await db.scalar(select(IncidentRow).where(IncidentRow.tenant_id==tenant_id,IncidentRow.related_finding_id==fid,IncidentRow.status.in_(["open","investigating"])).limit(1))
        if existing:
            out["reused_incidents"]+=1
            continue
        iid=await create_incident(tenant_id=tenant_id,title=title,description=f"Continuous attack-surface monitoring detected a {field} change.",severity="critical" if risk>=90 else "high",related={"scan_id":scan_id,"finding_id":fid},evidence=[{"type":"attack_surface","change":change,"risk_score":risk}])
        async with session_scope(tenant_id) as db:
            alert=await db.scalar(select(SecurityAlertRow).where(SecurityAlertRow.tenant_id==tenant_id,SecurityAlertRow.event_id==event["event_id"]).order_by(SecurityAlertRow.created_at.desc()).limit(1))
            if alert: alert.incident_id=iid
        out["incidents"]+=1
    return out
