"""2.5 - Import external scan results: ProjectDiscovery Nuclei JSONL output
(``nuclei -jsonl``). Not the template *format* (see 1.3's
``convert_nuclei_template.py`` for that) - this is Nuclei's *results*
output, for teams already running Nuclei outside MIRSAD who want the
findings merged into one MIRSAD view.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from app.modules.normalizer.normalizer import make_id
from app.schemas.platform import FindingEvidence, NormalizedFinding

_SEVERITY_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "unknown": "Info"}


def parse_nuclei_jsonl(text: str, scan_id: str) -> list[NormalizedFinding]:
    now = datetime.now(timezone.utc)
    out: list[NormalizedFinding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip malformed lines rather than failing the whole import
        info = row.get("info", {}) or {}
        template_id = row.get("template-id") or row.get("template_id") or f"line-{line_no}"
        title = info.get("name") or template_id
        severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "Info")
        asset = row.get("matched-at") or row.get("host") or row.get("matched_at") or "unknown"
        evidence_text = json.dumps(row.get("extracted-results") or row.get("extractor-name") or {}, ensure_ascii=False)[:2000] or title

        out.append(NormalizedFinding(
            finding_id=make_id("nuclei-import", template_id, asset, evidence_text),
            scan_id=scan_id,
            source_module="import-nuclei",
            rule_id=template_id,
            title=title,
            severity=severity,
            confidence=0.8,
            status="OPEN",
            verification_status="DETECTED",
            description=(info.get("description") or "نتيجة مستوردة من تشغيل Nuclei خارجي.") + " (مصدر: Nuclei JSONL مستورد)",
            evidence=[FindingEvidence(source="nuclei-import", asset=asset, evidence=evidence_text, confidence=0.8)],
            affected_asset=asset,
            references=(info.get("reference") or [])[:10] if isinstance(info.get("reference"), list) else [],
            tags=["imported", "nuclei"] + (info.get("tags") or []),
            first_seen=now,
            last_seen=now,
        ))
    return out
