"""Regional Threat Actor Profiles (Bet 1: regional sovereignty).

A small, curated, static reference of publicly-documented threat groups
whose reporting (MITRE ATT&CK Groups, vendor threat-intel writeups such as
Mandiant/Microsoft/CrowdStrike/CISA advisories) identifies them as
historically active against Middle Eastern / Gulf organizations. This is
context for a defender, not an attack tool: every entry is (a) already
public knowledge, (b) named at the group/technique level only - no
indicators of compromise, exploit code, or operational tradecraft - and (c)
mapped to MITRE ATT&CK technique IDs so it slots directly into the existing
attack-path/graph machinery instead of being a standalone list nobody reads.

This is intentionally NOT live intelligence (no feed, no scraping, no dark
web/Telegram monitoring - that requires an operator-supplied,
credentialed, actively-maintained pipeline that is out of scope for a
static code module and is called out as such in the roadmap). It is a
starting reference an analyst can extend; `custom_profiles.json` next to
this file (if present) is merged in without requiring a code change.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Each profile cites only what is already publicly attributed in open
# reporting (MITRE ATT&CK group pages and named vendor advisories), at the
# technique-ID level - never step-by-step tradecraft.
REGIONAL_THREAT_ACTORS: list[dict[str, Any]] = [
    {
        "id": "G0049",
        "name": "OilRig",
        "aliases": ["APT34", "Helix Kitten"],
        "region_focus": ["Gulf", "Middle East"],
        "sectors": ["government", "energy", "financial", "telecom"],
        "summary_ar": "مجموعة تهديد موثقة علنًا (MITRE ATT&CK G0049) بتاريخ استهداف منظمات حكومية وطاقة ومالية في الخليج والشرق الأوسط، تعتمد غالبًا على التصيد الموجّه والوصول عبر واجهات ويب مكشوفة.",
        "attck_techniques": ["T1566", "T1190", "T1059", "T1105"],
        "reference": "https://attack.mitre.org/groups/G0049/",
    },
    {
        "id": "G0069",
        "name": "MuddyWater",
        "aliases": ["Static Kitten", "Seedworm"],
        "region_focus": ["Middle East"],
        "sectors": ["government", "telecom", "oil_and_gas", "academia"],
        "summary_ar": "مجموعة تهديد موثقة علنًا (MITRE ATT&CK G0069) نشطة في الشرق الأوسط، معروفة باستغلال ثغرات في تطبيقات ويب مكشوفة وأدوات إدارة عن بعد شرعية لأغراض ضارة.",
        "attck_techniques": ["T1190", "T1219", "T1071"],
        "reference": "https://attack.mitre.org/groups/G0069/",
    },
    {
        "id": "G1002",
        "name": "BladedFeline",
        "aliases": [],
        "region_focus": ["Middle East"],
        "sectors": ["government", "telecom"],
        "summary_ar": "مجموعة تهديد موثقة علنًا نشطة ضد جهات حكومية واتصالات في الشرق الأوسط، معروفة باستهداف بنية تحتية مكشوفة على الإنترنت للحصول على موطئ قدم أولي.",
        "attck_techniques": ["T1190", "T1505"],
        "reference": "https://attack.mitre.org/groups/G1002/",
    },
    {
        "id": "G0064",
        "name": "APT33",
        "aliases": ["Elfin", "Refined Kitten"],
        "region_focus": ["Gulf", "Middle East"],
        "sectors": ["aviation", "energy", "petrochemical"],
        "summary_ar": "مجموعة تهديد موثقة علنًا (MITRE ATT&CK G0064) باستهداف تاريخي لقطاعي الطيران والطاقة/البتروكيماويات في الخليج.",
        "attck_techniques": ["T1566", "T1078", "T1583"],
        "reference": "https://attack.mitre.org/groups/G0064/",
    },
]


def _load_custom_profiles() -> list[dict[str, Any]]:
    """Optional operator-maintained extension file, merged without a code
    change. Missing/invalid file is a normal, silent no-op (same
    fail-safe-optional pattern as the external_clients.py API integrations)."""
    path = Path(__file__).with_name("custom_regional_actors.json")
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def all_profiles() -> list[dict[str, Any]]:
    return REGIONAL_THREAT_ACTORS + _load_custom_profiles()


def relevant_profiles(*, sector: str | None = None, tags: list[str] | None = None) -> list[dict[str, Any]]:
    """Filter to profiles relevant to a given sector and/or a scan's finding
    tags (e.g. a finding tagged 'exposure'/'admin-panel' maps to groups whose
    known techniques include T1190 initial-access-via-exposed-application).
    Advisory context only - never used to alter a finding's severity or
    verification status (same constraint as the rest of ai_analysis/risk_engine)."""
    tag_set = {str(t).lower() for t in (tags or [])}
    technique_hint = "T1190" if tag_set & {"exposure", "admin-panel", "api", "web"} else None
    out = []
    for profile in all_profiles():
        if sector and sector.lower() not in {s.lower() for s in profile.get("sectors", [])}:
            continue
        if technique_hint and technique_hint not in profile.get("attck_techniques", []):
            continue
        out.append(profile)
    return out
