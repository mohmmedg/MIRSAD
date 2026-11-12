"""Evidence gate for reportable security findings.

Detection and confirmation are deliberately separate: a scanner observation is
useful telemetry, but it is not a confirmed vulnerability without reproducible
evidence.  This module is pure and side-effect free so every scan entry point
applies the same conservative rule before correlation and reporting.
"""
from __future__ import annotations

from typing import Any
from datetime import datetime
import re

from app.schemas.platform import NormalizedFinding


EXTERNAL_EVIDENCE_SOURCES = {"zap", "nuclei", "sqlmap", "ghauri", "ffuf", "testssl", "nmap"}


def _has_concrete_evidence(finding: NormalizedFinding) -> bool:
    return any(str(item.evidence or "").strip() for item in finding.evidence)


def _requires_impact(finding: NormalizedFinding) -> bool:
    # A verified configuration observation need not claim exploitation. An
    # actual security vulnerability must prove impact, not just an HTTP error.
    return str(finding.category or "").lower() not in {
        "hardening-observation", "deployment-context", "attack-surface", "information-disclosure",
    }


def _valid_timestamp(value: str | None) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.utcoffset() is not None
    except (TypeError, ValueError):
        return False


def _http_request(value: str | None) -> bool:
    return re.match(r"(?i)^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?:/\S*|https?://\S+)\s+HTTP/[123](?:\.\d+)?", str(value or "")) is not None


def _http_response(value: str | None) -> bool:
    return re.match(r"(?i)^\s*HTTP/[123](?:\.\d+)?\s+[1-5]\d{2}\b", str(value or "")) is not None


def _independent_verified(value: str | None) -> bool:
    # A bare yes/true or tool name is not an independent verification result.
    # The canonical verification record must still be audited by an analyst.
    return re.fullmatch(r"[a-zA-Z0-9._-]+:verified", str(value or "").strip()) is not None


def apply_confirmation_gate(findings: list[NormalizedFinding]) -> dict[str, Any]:
    """Apply the report-confirmation contract in-place and return reconciliation.

    A result is ``CONFIRMED`` only when its explicit verifier recorded a method,
    timestamp and concrete evidence. Results parsed from external engines also
    need a canonical raw artifact link. All other results remain candidates;
    they are retained for analyst review but cannot be presented as confirmed.
    """
    counts = {"confirmed": 0, "candidates": 0, "demoted": 0, "missing_provenance": 0}
    for finding in findings:
        finding.confirmation_state = "CANDIDATE"
        # The absence of a header/CORS control is hardening telemetry, not a
        # vulnerability without an independently demonstrated security impact.
        rule = str(finding.rule_id or "").upper()
        if not finding.security_impact and rule.startswith((
            "WEB-HEADER-CONFIG-", "WEB-CORS-CONFIG", "WEB-SERVER-DISCLOSURE",
        )):
            finding.category = "hardening-observation"
        verification = str(finding.verification_status or "").upper()
        if verification in {"FALSE_POSITIVE", "REJECTED"}:
            finding.assessment_state = "FALSE_POSITIVE"
        elif verification in {"NOT_APPLICABLE", "NOT_TESTED"}:
            finding.assessment_state = "NOT_TESTED"
        else:
            finding.assessment_state = "INCONCLUSIVE"
        reasons: list[str] = []
        if str(finding.verification_status or "").upper() != "VERIFIED":
            reasons.append("no_verified_result")
        if not str(finding.verification_method or "").strip():
            reasons.append("missing_verification_method")
        if not str(finding.verification_timestamp or "").strip():
            reasons.append("missing_verification_timestamp")
        elif not _valid_timestamp(finding.verification_timestamp):
            reasons.append("invalid_verification_timestamp")
        if not _has_concrete_evidence(finding):
            reasons.append("missing_concrete_evidence")
        if not str(finding.affected_asset or "").startswith(("http://", "https://")):
            reasons.append("missing_affected_url")
        if not str(finding.method or "").strip():
            reasons.append("missing_http_method")
        if not str(finding.request or "").strip():
            reasons.append("missing_reproducible_request")
        elif not _http_request(finding.request):
            reasons.append("invalid_reproducible_request")
        if not str(finding.response or "").strip():
            reasons.append("missing_reproducible_response")
        elif not _http_response(finding.response):
            reasons.append("invalid_reproducible_response")
        if not str(finding.verification_replay or "").strip():
            reasons.append("missing_replay_steps")
        if _requires_impact(finding) and not str(finding.security_impact or "").strip():
            reasons.append("missing_security_impact")
        if finding.severity in {"High", "Critical"} and not _independent_verified(finding.independent_verification):
            reasons.append("missing_independent_verification")
        if not finding.raw_artifact_id:
            reasons.append("missing_raw_artifact")
        digest = str(finding.raw_artifact_sha256 or "").strip()
        if re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            reasons.append("missing_or_invalid_artifact_sha256")
        if finding.source_module in EXTERNAL_EVIDENCE_SOURCES and not str(finding.tool_version or "").strip():
            reasons.append("missing_tool_version")
        if finding.source_module in EXTERNAL_EVIDENCE_SOURCES and not finding.raw_artifact_id:
            reasons.append("missing_raw_artifact")
            counts["missing_provenance"] += 1
        if finding.source_module in EXTERNAL_EVIDENCE_SOURCES and not finding.execution_id:
            reasons.append("missing_execution_id")
            counts["missing_provenance"] += 1
        if reasons:
            if (verification == "VERIFIED" and
                {"missing_independent_verification", "missing_replay_steps"}.intersection(reasons) and
                "missing_reproducible_request" not in reasons and
                "missing_reproducible_response" not in reasons and
                "missing_security_impact" not in reasons and
                "missing_or_invalid_artifact_sha256" not in reasons):
                finding.assessment_state = "LIKELY"
            was_verified = str(finding.verification_status or "").upper() == "VERIFIED"
            if was_verified:
                finding.verification_status = "DETECTED"
                counts["demoted"] += 1
            finding.confirmation_reason = ";".join(reasons)
            finding.tags = list(dict.fromkeys([*finding.tags, "candidate", "confirmation-gate"] ))
            counts["candidates"] += 1
            continue
        finding.confirmation_state = "CONFIRMED"
        finding.assessment_state = "CONFIRMED"
        finding.confirmation_reason = "reproducible_verification_evidence_present"
        finding.tags = [tag for tag in finding.tags if tag not in {"candidate", "confirmation-gate"}]
        finding.tags = list(dict.fromkeys([*finding.tags, "confirmed"]))
        counts["confirmed"] += 1
    return {"status": "COMPLETED", "total": len(findings), **counts}
