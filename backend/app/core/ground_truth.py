"""Version-pinned, offline regression metrics for an *operator supplied* lab manifest.

Do not ship a fabricated Juice Shop challenge catalog. A ground-truth manifest
must name the exact installed lab version and the positive/negative scenarios
that the operator has independently validated against that version.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from app.schemas.platform import UnifiedScanResult


def _field(item: Any, name: str, default=None):
    return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)


def _signature(item: Any) -> tuple[str, str, str, str]:
    url = str(_field(item, "path") or _field(item, "affected_asset") or "")
    path = urlsplit(url).path or "/"
    return (str(_field(item, "rule_id") or "").casefold(),
            path.rstrip("/") or "/",
            str(_field(item, "method") or "GET").upper(),
            str(_field(item, "parameter") or "").casefold())


def _prove(finding: Any) -> bool:
    """Recheck minimal durable proof so the completeness KPI cannot be spoofed."""
    return all(str(_field(finding, field) or "").strip() for field in (
        "request", "response", "verification_method", "verification_timestamp",
        "verification_replay", "raw_artifact_id",
    )) and bool(re.fullmatch(r"[a-fA-F0-9]{64}", str(_field(finding, "raw_artifact_sha256") or ""))) and (
        str(_field(finding, "category") or "").lower() in {
            "hardening-observation", "deployment-context", "attack-surface", "information-disclosure",
        } or bool(str(_field(finding, "security_impact") or "").strip()))


def evaluate_ground_truth(scan: UnifiedScanResult, manifest: dict) -> dict[str, Any]:
    """Evaluate known positive and negative scenarios without claiming unknowns false.

    ``precision`` is among classified confirmed findings only.  Unclassified
    confirmed findings are reported separately; they are NOT false positives.
    False-positive rate uses *tested known negatives* as its denominator, and
    is undefined (null) if no known negative was tested.  A detected candidate
    never counts as a successfully verified scenario.
    """
    if manifest.get("lab") != "OWASP Juice Shop":
        raise ValueError("lab must be OWASP Juice Shop")
    if not str(manifest.get("version") or "").strip():
        raise ValueError("version is required; an unpinned ground truth is not valid")
    positives = manifest.get("positive_scenarios") or []
    negatives = manifest.get("negative_scenarios") or []
    if not isinstance(positives, list) or not isinstance(negatives, list):
        raise ValueError("positive_scenarios and negative_scenarios must be lists")
    ids = [s.get("id") for s in positives + negatives]
    if not all(isinstance(i, str) and i.strip() for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("scenario ids must be nonempty and unique")
    for scenario in positives + negatives:
        if not scenario.get("rule_id") or not scenario.get("path"):
            raise ValueError("each scenario requires rule_id and path")
        if not str(scenario["path"]).startswith("/"):
            raise ValueError("scenario path must be an absolute route beginning with /")

    good = {_signature(s): s["id"] for s in positives}
    bad = {_signature(s): s["id"] for s in negatives}
    if set(good) & set(bad):
        raise ValueError("positive and negative scenario signatures overlap")
    if len(good) != len(positives) or len(bad) != len(negatives):
        raise ValueError("duplicate scenario signatures are not allowed")

    confirmed = [f for f in scan.findings if _field(f, "confirmation_state") == "CONFIRMED"]
    found = {_signature(f) for f in confirmed}
    true_positive = [f for f in confirmed if _signature(f) in good]
    false_positive = [f for f in confirmed if _signature(f) in bad]
    unclassified = [f for f in confirmed if _signature(f) not in good and _signature(f) not in bad]
    covered = {s["id"] for s in positives if _signature(s) in found}

    matrix = list(_field(scan.coverage, "endpoint_matrix", []) or [])
    tested = [e for e in matrix if str(e.get("security_state") or "").upper() in {"TESTED", "VERIFIED"}]
    tested_routes = {(urlsplit(str(e.get("url") or "")).path.rstrip("/") or "/",
                      str(e.get("method") or "GET").upper()) for e in tested}
    tested_negatives = [s for s in negatives if (_signature(s)[1], _signature(s)[2]) in tested_routes]
    known_tn = len(tested_negatives) - sum(_signature(s) in found for s in tested_negatives)
    tp, fp = len(true_positive), len(false_positive)
    # FPR is FP / (FP + TN), not FP / total findings. Known negatives
    # only count as TN if the corresponding route/method was actually tested.
    fp_tested = sum(_signature(s) in found for s in tested_negatives)
    denominator = fp_tested + known_tn
    return {
        "lab": "OWASP Juice Shop",
        "lab_version": manifest["version"],
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "precision_scope": "only confirmed findings classified in this version-pinned manifest",
        "recall": round(len(covered) / len(positives), 4) if positives else None,
        "false_positive_rate": round(fp_tested / denominator, 4) if denominator else None,
        "endpoint_coverage": round(len(tested) / len(matrix), 4) if matrix else None,
        "evidence_completeness": round(sum(_prove(f) for f in confirmed) / len(confirmed), 4) if confirmed else None,
        "confirmed_count": len(confirmed),
        "candidate_count": len(scan.findings) - len(confirmed),
        "true_positive_count": tp,
        "false_positive_count": fp,
        "unclassified_confirmed": len(unclassified),
        "uncovered_scenarios": [s["id"] for s in positives if s["id"] not in covered],
        "skipped_endpoints": [{"url": e.get("url"), "method": e.get("method"),
                               "reason": e.get("reason") or "not recorded"}
                              for e in matrix if str(e.get("security_state") or "").upper() not in {"TESTED", "VERIFIED"}],
        "known_negative_scenarios_tested": len(tested_negatives),
    }
