"""Regression tests for the 2026-10-10 detection/reporting audit."""
import ast
from pathlib import Path

from app.modules.external_scanners.engines import parse_ffuf_json, _auth_header_pairs
from app.modules.normalizer.normalizer import normalize_external_scanners
from app.modules.risk_engine.engine import score_finding


def _score(sev, verified="VERIFIED", conf=0.95):
    return score_finding(sev, conf, True, exploitability=1.0, exposure=0.85, asset_criticality=0.5,
                         evidence_quality_score=1.0, verification_status=verified)


def test_verified_critical_reaches_p1_and_high_reaches_p2():
    assert _score("Critical") >= 85
    assert _score("High") >= 60
    assert _score("Medium") < 60
    assert _score("Info") == 0.0


def test_verification_and_confidence_still_lower_score():
    assert _score("High", "VERIFIED") > _score("High", "DETECTED") > _score("High", "UNVERIFIED")
    assert _score("High", conf=0.9) > _score("High", conf=0.4)


def test_nuclei_detected_critical_is_not_buried_in_p3():
    assert _score("Critical", "DETECTED", 0.75) >= 60


def test_finding_pipeline_imports_re():
    # This file lives directly under backend/tests/ (not backend/tests/unit/), so
    # parents[1] is backend/ - parents[2] overshoots to the project root one level
    # above backend/, where app/core/finding_pipeline.py does not exist.
    src = Path(__file__).resolve().parents[1].joinpath("app/core/finding_pipeline.py").read_text()
    imported = {a.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Import) for a in n.names}
    assert "re" in imported


def test_ffuf_sensitive_paths_are_not_all_info():
    out = parse_ffuf_json({"results": [
        {"url": "http://t/.git/HEAD", "status": 200, "words": 1, "length": 20},
        {"url": "http://t/phpmyadmin/", "status": 200, "words": 1, "length": 20},
        {"url": "http://t/admin", "status": 403, "words": 1, "length": 20},
        {"url": "http://t/about", "status": 200, "words": 1, "length": 20},
    ]})
    assert [f["severity"] for f in out] == ["High", "Medium", "Info", "Info"]
    assert out[0]["rule_id"].startswith("FFUF-")


def test_external_findings_without_native_rule_get_stable_rule_id():
    ext = {"sqlmap": {"status": "COMPLETED", "findings": [{"name": "SQL injection reported by sqlmap", "severity": "High", "matched_at": "http://t/i?id=1", "parameter": "id", "type": "boolean-based blind"}]}}
    f = normalize_external_scanners(ext, scan_id="s", target="http://t/")[0]
    assert f.rule_id.startswith("SQLMAP-")


def test_auth_header_pairs_reject_header_injection():
    assert _auth_header_pairs("Bearer abc", "sid=1") == [("Authorization", "Bearer abc"), ("Cookie", "sid=1")]
    assert _auth_header_pairs("Bearer a\r\nX: y", None) == []
    assert _auth_header_pairs(None, None) == []


def test_report_contains_per_tool_section():
    from app.modules.reporting.generator import _engine_results_lines

    class S:
        external_scanners = {"zap": {"status": "COMPLETED", "mode": "passive+client-spider", "findings": [{"risk": "Low"}], "duration_seconds": 12},
                             "nuclei": {"status": "UNAVAILABLE", "findings": [], "reason": "binary not found"}}
        advanced_security = {}
    for lang in ("ar", "en"):
        text = "\n".join(_engine_results_lines(S(), lang))
        assert "zap" in text and "passive+client-spider" in text and "binary not found" in text
