"""Regression tests for the gap-closing items added on top of the
2026-09-12 audit: the what-if remediation simulation, VirusTotal as a
subdomain source, config-snippet remediation, and regional threat-actor
profiles."""
import pytest

from app.modules.risk_engine.engine import organization_score, simulate_fix_impact
from app.modules.threat_intel.regional_threat_actors import all_profiles, relevant_profiles


def _scan(target, findings):
    return {"target": target, "scan_id": target, "findings": findings}


def _finding(fid, severity="High", confidence=0.9):
    return {
        "finding_id": fid, "source_module": "web", "title": "t", "severity": severity,
        "confidence": confidence, "description": "d", "evidence": [], "tags": [],
        "affected_asset": "a", "verification_status": "VERIFIED",
    }


def test_what_if_simulation_never_mutates_input_and_lowers_score():
    scans = [_scan("a.example.com", [_finding("f1"), _finding("f2"), _finding("f3")])]
    before = organization_score(scans)
    result = simulate_fix_impact(scans, ["f1", "f2"])
    assert result["before"]["score"] == before["score"]
    assert result["after"]["score"] <= result["before"]["score"]
    assert result["findings_removed"] == 2
    # input list itself must be untouched (no findings actually "fixed")
    assert len(scans[0]["findings"]) == 3


def test_what_if_simulation_no_ids_is_a_no_op():
    scans = [_scan("a.example.com", [_finding("f1")])]
    result = simulate_fix_impact(scans, [])
    assert result["delta"] == 0.0
    assert result["findings_removed"] == 0


def test_virustotal_registered_as_subdomain_plugin_source():
    import app.modules.technology.subdomain_discovery  # noqa: F401 - triggers registration
    from app.modules.plugin_registry import registry
    names = {p["name"] for p in registry.list() if p["kind"] == "subdomain_source"}
    assert "subdomain_source.virustotal" in names


@pytest.mark.asyncio
async def test_virustotal_subdomain_source_noop_without_key(monkeypatch):
    from app.core.config import settings
    from app.modules.technology.subdomain_discovery import source_virustotal
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    assert await source_virustotal("example.com") == {}


@pytest.mark.asyncio
async def test_suggest_remediation_includes_config_snippet_for_headers_tag():
    from app.modules.ai_analysis.analyzer import AIAnalyzer
    analyzer = AIAnalyzer()
    analyzer._client = None  # force deterministic template path
    result = await analyzer.suggest_remediation(
        {"title": "Missing security headers", "tags": ["headers"], "severity": "Medium"}
    )
    assert result["config_snippet"] is not None
    assert "nginx" in result["config_snippet"]


@pytest.mark.asyncio
async def test_suggest_remediation_config_snippet_none_for_unmapped_tag():
    from app.modules.ai_analysis.analyzer import AIAnalyzer
    analyzer = AIAnalyzer()
    analyzer._client = None
    result = await analyzer.suggest_remediation(
        {"title": "Something unusual", "tags": ["completely-unmapped-tag"], "severity": "Low"}
    )
    assert result["config_snippet"] is None


def test_regional_threat_actor_profiles_are_public_and_technique_mapped():
    profiles = all_profiles()
    assert len(profiles) >= 4
    for p in profiles:
        assert p["attck_techniques"]
        assert p["reference"].startswith("https://")


def test_regional_threat_actor_filter_by_sector():
    energy = relevant_profiles(sector="energy")
    assert energy
    assert all("energy" in [s.lower() for s in p["sectors"]] for p in energy)


def test_regional_threat_actor_filter_by_exposure_tags_maps_to_t1190():
    matched = relevant_profiles(tags=["exposure"])
    assert matched
    assert all("T1190" in p["attck_techniques"] for p in matched)
