"""Deterministic, auditable risk engine used by every scan/report path."""
from app.schemas.platform import NormalizedFinding, RiskAssessment

RISK_ENGINE_VERSION = "2.0"
WEIGHTS = {"Critical": 1.0, "High": 0.78, "Medium": 0.52, "Low": 0.28, "Info": 0.0}
VERIFICATION_FACTOR = {"VERIFIED": 1.0, "DETECTED": 0.85, "UNVERIFIED": 0.65, "REJECTED": 0.0}
EVIDENCE_FACTOR = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6}

def evidence_quality(f: NormalizedFinding) -> str:
    if not f.evidence:
        return "LOW"
    if len(f.evidence) >= 2 or any(len(e.evidence) >= 160 for e in f.evidence):
        return "HIGH"
    return "MEDIUM"

def score_finding(
    severity: str,
    confidence: float,
    has_corroborating_evidence: bool,
    *,
    exploitability: float = 1.0,
    exposure: float = 1.0,
    asset_criticality: float = 1.0,
    evidence_quality_score: float | None = None,
    verification_status: str = "UNVERIFIED",
    in_kev: bool = False,
) -> float:
    base = WEIGHTS.get(severity, 0.0) * 100
    confidence = min(1.0, max(0.0, confidence))
    evidence = evidence_quality_score if evidence_quality_score is not None else (1.0 if has_corroborating_evidence else 0.6)
    verification = VERIFICATION_FACTOR.get(verification_status, 0.65)
    # Calibration (2026-10-10): the previous formula multiplied six factors
    # together, so even a VERIFIED Critical finding scored ~50-64 and could
    # never reach P1 (>=85) / trigger SOC alerts (>=60/70). Severity is now the
    # anchor; certainty (confidence x evidence x verification) and context
    # (exploitability/exposure/criticality) only modulate it:
    #   certainty 1.0 -> x1.00, certainty 0.5 -> x0.80
    #   context   1.0 -> x1.00, context   0.5 -> x0.925
    # Verified Critical ~95 (P1), verified High ~74 (P2), verified Medium ~50 (P3).
    certainty = max(0.0, min(1.0, confidence)) * evidence * verification
    context = (max(0.0, min(1.0, exploitability)) + max(0.0, min(1.0, exposure))
               + max(0.0, min(1.0, asset_criticality))) / 3.0
    score = min(100.0, base * (0.6 + 0.4 * certainty) * (0.85 + 0.15 * context))
    if in_kev:
        KEV_FLOOR = 70.0  # a KEV-linked finding never scores below the High range
        score = max(score, min(100.0, KEV_FLOOR + 10.0 * confidence))
    return round(score, 1)

def bundle(scores: list[float]) -> float:
    if not scores:
        return 0.0
    top = sorted((max(0.0, min(100.0, s)) for s in scores), reverse=True)
    # Stable aggregation: strongest three dominate, remaining findings add breadth.
    # 2026-10-17: the old linear sum (top3 x 0.55) exceeded 100 as soon as three
    # high-scoring findings existed, so it was clamped and a bad scan and a catastrophic
    # scan both showed 100. Findings are now combined as independent "risk
    # contributions" (noisy-OR): result = 1 - prod(1 - p_i). A single finding keeps its
    # old value (score x 0.55), more findings raise the total with diminishing returns,
    # it can never exceed 100 without clamping, and removing a finding never raises it.
    remaining = 1.0
    for rank, s in enumerate(top[:10]):
        weight = 0.55 if rank < 3 else 0.08
        remaining *= 1.0 - (s / 100.0) * weight
    return round(100.0 * (1.0 - remaining), 1)

def _context_factor(f: NormalizedFinding, key: str, default: float) -> float:
    if key in f.risk_context:
        return max(0.0, min(1.0, float(f.risk_context[key])))
    return default

def assess(f: NormalizedFinding) -> RiskAssessment:
    if getattr(f, "confirmation_state", "CANDIDATE") != "CONFIRMED":
        return RiskAssessment(score=0.0, severity=f.severity, confidence=f.confidence,
                              factors={"confirmation_pending": 1.0})
    if getattr(f, "category", "") in {"hardening-observation", "deployment-context"}:
        return RiskAssessment(score=0.0, severity=f.severity, confidence=f.confidence,
                              factors={"non_exploitable_observation": 1.0})
    quality = evidence_quality(f)
    quality_score = EVIDENCE_FACTOR[quality]
    # Deterministic contextual defaults. Explicit scanner context overrides them.
    exploitability_default = {"Critical": 1.0, "High": 0.85, "Medium": 0.65, "Low": 0.35, "Info": 0.1}.get(f.severity, 0.5)
    exposure_default = 0.85 if (f.affected_asset and ("/" in f.affected_asset or "http" in f.affected_asset.lower())) else 0.6
    criticality_default = 0.8 if any(x in " ".join(f.tags).lower() for x in ("auth", "session", "payment", "admin", "sensitive")) else 0.5
    exploitability = _context_factor(f, "exploitability", exploitability_default)
    exposure = _context_factor(f, "exposure", exposure_default)
    asset_criticality = _context_factor(f, "asset_criticality", criticality_default)
    in_kev = bool(f.risk_context.get("in_kev", False))
    score = score_finding(
        f.severity, f.confidence, bool(f.evidence),
        exploitability=exploitability, exposure=exposure, asset_criticality=asset_criticality,
        evidence_quality_score=quality_score,
        verification_status=f.verification_status,
        in_kev=in_kev,
    )
    return RiskAssessment(
        score=score, severity=f.severity, confidence=round(min(1.0, max(0.0, f.confidence)), 2),
        factors={
            "severity_weight": WEIGHTS.get(f.severity, 0.0),
            "confidence": round(f.confidence, 2),
            "exploitability": exploitability,
            "exposure": exposure,
            "asset_criticality": asset_criticality,
            "evidence_quality": quality_score,
            "verification": VERIFICATION_FACTOR.get(f.verification_status, 0.65),
            "in_kev": in_kev,
        },
    )

def _finding_severity(f) -> str:
    if isinstance(f, dict):
        return f.get("severity", "Info")
    return getattr(f, "severity", "Info")


def _finding_score(f) -> float:
    """Prefers an already-computed risk score (CorrelatedFinding.risk.score,
    or the equivalent JSON-dumped {"risk": {"score": ...}} shape from a
    persisted scan snapshot) over recomputing it, since organization_score()
    is typically fed historical snapshot dicts, not fresh NormalizedFinding
    objects mid-pipeline. Falls back to assess() only when no precomputed
    score is present."""
    if isinstance(f, dict):
        risk = f.get("risk")
        if isinstance(risk, dict) and risk.get("score") is not None:
            return float(risk["score"])
        try:
            return assess(NormalizedFinding(**{k: v for k, v in f.items() if k != "risk"})).score
        except Exception:
            return 0.0
    risk = getattr(f, "risk", None)
    if risk is not None and getattr(risk, "score", None) is not None:
        return float(risk.score)
    return assess(f).score


def _confirmed_risk(f) -> bool:
    value = f.get("confirmation_state") if isinstance(f, dict) else getattr(f, "confirmation_state", None)
    return value == "CONFIRMED" and (
        f.get("category") if isinstance(f, dict) else getattr(f, "category", "security")
    ) not in {"hardening-observation", "deployment-context"}


def bundle_score(findings):
    return bundle([_finding_score(f) for f in findings
                   if _finding_severity(f) != "Info" and _confirmed_risk(f)])


def _finding_id(f) -> str | None:
    if isinstance(f, dict):
        return f.get("finding_id")
    return getattr(f, "finding_id", None)


def organization_score(scans: list) -> dict:
    """2.3: MIRSAD Score — an organization-wide aggregate across every asset,
    distinct from bundle_score() (which scores one scan's finding set).

    `scans` is any iterable of objects/dicts exposing `.findings` (or
    `["findings"]`) and `.target`/`.scan_id` — i.e. persisted scan snapshots
    (see supabase/migrations/0009_scan_snapshots.sql), so this can be called
    either against a fresh batch of scan results or against the historical
    snapshot table for trend tracking.

    The weighted average intentionally does NOT just average every asset's
    bundle_score equally: an asset with more findings and higher bundle_score
    should pull the organization number down harder than a quiet, clean
    asset pulls it up, which a flat mean would understate for an
    organization with one badly-exposed asset among many clean ones.
    """
    per_asset: list[dict] = []
    for scan in scans:
        findings = getattr(scan, "findings", None)
        if findings is None and isinstance(scan, dict):
            findings = scan.get("findings")
        findings = findings or []
        target = getattr(scan, "target", None) or (scan.get("target") if isinstance(scan, dict) else None) or "unknown"
        scan_id = getattr(scan, "scan_id", None) or (scan.get("scan_id") if isinstance(scan, dict) else None)
        score = bundle_score(findings)
        weight = 1.0 + min(2.0, 0.15 * len([f for f in findings if _finding_severity(f) in {"Critical", "High"}]))
        per_asset.append({"target": target, "scan_id": scan_id, "score": score, "weight": weight, "finding_count": len(findings)})

    if not per_asset:
        return {"score": 0.0, "assets": [], "asset_count": 0, "generated_at": None}

    weighted_sum = sum(a["score"] * a["weight"] for a in per_asset)
    total_weight = sum(a["weight"] for a in per_asset) or 1.0
    org_score = round(min(100.0, weighted_sum / total_weight), 1)
    from datetime import datetime, timezone
    return {
        "score": org_score,
        "assets": sorted(per_asset, key=lambda a: a["score"], reverse=True),
        "asset_count": len(per_asset),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def simulate_fix_impact(scans: list, fixed_finding_ids: set[str] | list[str]) -> dict:
    """Advisory-only 'what-if' simulation (Bet 2 / agentic-AI layer item):
    "if we fixed these N findings, how much would the MIRSAD Score drop?"

    Does not mutate anything and never claims a fix was actually applied -
    it recomputes organization_score() on the same snapshot set with the
    given finding_ids excluded, purely as a planning aid. Reuses
    organization_score()/bundle_score() byte-for-byte so the simulated
    number is computed by the exact same deterministic formula as the real
    score, never a separate/divergent estimate.
    """
    fixed_ids = {str(x) for x in (fixed_finding_ids or [])}
    before = organization_score(scans)
    if not fixed_ids:
        return {"before": before, "after": before, "delta": 0.0, "findings_removed": 0}

    simulated_scans: list[dict] = []
    removed = 0
    for scan in scans:
        findings = getattr(scan, "findings", None)
        if findings is None and isinstance(scan, dict):
            findings = scan.get("findings")
        findings = findings or []
        target = getattr(scan, "target", None) or (scan.get("target") if isinstance(scan, dict) else None)
        scan_id = getattr(scan, "scan_id", None) or (scan.get("scan_id") if isinstance(scan, dict) else None)
        kept = [f for f in findings if _finding_id(f) not in fixed_ids]
        removed += len(findings) - len(kept)
        simulated_scans.append({"target": target, "scan_id": scan_id, "findings": kept})

    after = organization_score(simulated_scans)
    return {
        "before": before,
        "after": after,
        "delta": round(after["score"] - before["score"], 1),
        "findings_removed": removed,
    }
