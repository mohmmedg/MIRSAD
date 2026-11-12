"""2.5 - Import external scan results: Tenable Nessus (.nessus XML).

Feeds the same ``app.schemas.platform.NormalizedFinding`` shape that
``app.modules.normalizer.normalizer`` already produces for MIRSAD's own
scanners, so imported findings flow through every downstream step (risk
engine, attack-chain hints, compliance gating, notifications) unmodified -
this module only *translates*, it never bypasses assessment.
"""
from __future__ import annotations

from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as DefusedET  # blocks entity expansion / external entities

from app.modules.normalizer.normalizer import make_id
from app.schemas.platform import FindingEvidence, NormalizedFinding

_SEVERITY_BY_NESSUS_LEVEL = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"}


def parse_nessus_xml(xml_bytes: bytes, scan_id: str) -> list[NormalizedFinding]:
    """Parse a .nessus file's ``<ReportHost>``/``<ReportItem>`` tree.

    Non-vulnerability plugin families (informational-only "plugin" noise
    with severity 0 and no description) are skipped by default to avoid
    flooding the findings list - Nessus reports commonly contain hundreds of
    pure-info plugins that aren't actionable security findings.
    """
    now = datetime.now(timezone.utc)
    try:
        root = DefusedET.fromstring(xml_bytes)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError(f"ملف .nessus غير صالح: {exc}") from None

    out: list[NormalizedFinding] = []
    for host in root.iter("ReportHost"):
        host_name = host.get("name") or "unknown-host"
        for item in host.iter("ReportItem"):
            severity_raw = item.get("severity", "0")
            severity = _SEVERITY_BY_NESSUS_LEVEL.get(severity_raw, "Info")
            plugin_name = item.get("pluginName") or item.get("pluginID") or "Nessus finding"
            port = item.get("port", "0")
            protocol = item.get("protocol", "tcp")
            svc_name = item.get("svc_name", "")
            asset = f"{host_name}:{port}/{protocol}" if port not in ("0", "") else host_name

            if severity == "Info" and not (item.findtext("description") or "").strip():
                continue

            description = (item.findtext("description") or item.findtext("synopsis") or "").strip()
            solution = (item.findtext("solution") or "").strip()
            plugin_output = (item.findtext("plugin_output") or "").strip()
            cve_list = [c.text for c in item.findall("cve") if c.text]
            cvss3 = item.findtext("cvss3_base_score")

            evidence_text = plugin_output or description or plugin_name
            base_description = description or f"نتيجة مستوردة من Nessus لخدمة {svc_name or protocol} على {asset}."
            out.append(NormalizedFinding(
                finding_id=make_id("nessus-import", plugin_name, asset, evidence_text),
                scan_id=scan_id,
                source_module="import-nessus",
                rule_id=item.get("pluginID"),
                title=plugin_name,
                severity=severity,
                confidence=0.75,  # imported, not independently re-verified by MIRSAD
                status="OPEN",
                verification_status="DETECTED",
                description=base_description + " (مصدر الاكتشاف: مستورد من Nessus - .nessus XML)",
                evidence=[FindingEvidence(source="nessus-import", asset=asset, evidence=evidence_text[:3000], confidence=0.75)],
                affected_asset=asset,
                remediation=solution or None,
                references=cve_list[:10],
                tags=["imported", "nessus"] + (["cvss:" + cvss3] if cvss3 else []),
                first_seen=now,
                last_seen=now,
            ))
    return out
