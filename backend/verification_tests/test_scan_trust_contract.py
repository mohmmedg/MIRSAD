"""Offline, deterministic regressions for scan truthfulness and evidence quality."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.core.finding_confirmation import apply_confirmation_gate
from app.modules.correlator.correlator import correlate
from app.modules.risk_engine.engine import bundle_score
from app.modules.advanced_security import AdvancedSecurityEngine
from app.modules.reporting.generator import generate_markdown
from app.modules.reporting.exporters import to_json, to_sarif
from app.schemas.platform import FindingEvidence, NormalizedFinding, UnifiedScanResult


URL = "https://example.com/api/items/1"


def finding(**overrides):
    base = dict(finding_id="f1", source_module="sqlmap", rule_id="SQLI-1", title="Possible SQLi",
                severity="High", affected_asset=URL, method="GET", parameter="id",
                verification_status="VERIFIED", verification_method="independent-readonly-replay",
                verification_timestamp="2026-11-10T12:00:00Z", execution_id="exec-1",
                raw_artifact_id="art-1", raw_locator="line:1",
                evidence=[FindingEvidence(source="sqlmap", asset=URL, evidence="safe replay observed")])
    base.update(overrides)
    return NormalizedFinding(**base)


def complete_proof(**overrides):
    proof = dict(request="GET /api/items/1?id=1 HTTP/1.1", response="HTTP/1.1 200 OK\nX-Test: 1",
                 raw_artifact_sha256=hashlib.sha256(b"test").hexdigest(),
                 verification_replay="Replay GET with safe marker; compare returned marker",
                 security_impact="Cross-user access demonstrated using two test accounts",
                 independent_verification="second-tool-replay:verified", tool_version="test-1.0")
    proof.update(overrides)
    return finding(**proof)


def snapshot(findings):
    now = datetime.now(timezone.utc)
    return UnifiedScanResult(scan_id="scan-1", target="https://example.com", status="partial",
                             started_at=now, findings=correlate(findings), risk_score=bundle_score(correlate(findings)))


def test_external_unproven_candidate_cannot_raise_scan_risk():
    f = finding()
    apply_confirmation_gate([f])
    assert f.confirmation_state == "CANDIDATE"
    assert "missing_reproducible_request" in f.confirmation_reason
    assert bundle_score(correlate([f])) == 0.0
    s = snapshot([f])
    assert s.risk_score == 0.0
    assert "Candidates" in generate_markdown(s, language="en")
    assert "Confirmed Findings" in generate_markdown(s, language="en")
    assert not to_json(s, audience="managerial")["findings"]
    assert to_sarif(s)["runs"][0]["results"][0]["level"] == "none"


def test_proven_high_finding_requires_independent_replay():
    f = complete_proof(independent_verification=None)
    apply_confirmation_gate([f])
    assert f.confirmation_state == "CANDIDATE"
    assert "missing_independent_verification" in f.confirmation_reason
    f2 = complete_proof()
    apply_confirmation_gate([f2])
    assert f2.confirmation_state == "CONFIRMED"
    assert bundle_score(correlate([f2])) > 0


def test_bad_hash_does_not_confirm():
    f = complete_proof(raw_artifact_sha256="bad")
    apply_confirmation_gate([f])
    assert f.confirmation_state == "CANDIDATE"


@pytest.mark.asyncio
async def test_advanced_security_failure_is_not_success(monkeypatch):
    import app.modules.advanced_security as mod
    monkeypatch.setattr(mod, "verify_target_in_scope", lambda _: None)
    eng = AdvancedSecurityEngine()
    names = ["_websocket_messages", "_graphql", "_parser_injections", "_request_smuggling", "_cache_security",
             "_file_upload", "_race_conditions", "_business_logic", "_auth_workflows", "_dom_xss", "_command_injection"]
    async def failed(*args, **kwargs):
        return {"status": "FAILED", "coverage": {}, "findings": []}
    for name in names:
        monkeypatch.setattr(eng, name, failed)
    value = await eng.scan("https://example.com", web=None, api=None, safe_mode="safe", destructive_confirmation=False)
    assert value["status"] == "FAILED"
    assert value["finding_count"] == 0
    assert len(value["engines"]) >= len(names)


@pytest.mark.asyncio
async def test_advanced_security_phase_timeout_reports_partial(monkeypatch):
    import app.modules.advanced_security as mod
    monkeypatch.setattr(mod, "verify_target_in_scope", lambda _: None)
    monkeypatch.setattr(mod.settings, "ADVANCED_SECURITY_PHASE_TIMEOUT_SECONDS", 0.01, raising=False)
    eng = AdvancedSecurityEngine()
    names = ["_websocket_messages", "_graphql", "_parser_injections", "_request_smuggling", "_cache_security",
             "_file_upload", "_race_conditions", "_business_logic", "_auth_workflows", "_dom_xss", "_command_injection"]
    async def succeeded(*args, **kwargs):
        return {"status": "COMPLETED", "coverage": {}, "findings": []}
    async def hung(*args, **kwargs):
        await asyncio.sleep(0.2)
        return {"status": "COMPLETED", "coverage": {}, "findings": []}
    for name in names:
        monkeypatch.setattr(eng, name, succeeded)
    monkeypatch.setattr(eng, "_graphql", hung)
    value = await eng.scan("https://example.com", web=None, api=None, safe_mode="safe", destructive_confirmation=False)
    assert value["status"] == "PARTIAL"
    assert value["engines"]["graphql_advanced"] == "TIMEOUT"
    assert any("graphql_advanced" in reason for reason in value["warnings"])


def test_external_outcomes_cannot_mask_partial_or_unknown_tools():
    from app.core.scan_health import external_stage_status, web_terminal_status
    tools = {"nuclei": {"status": "COMPLETED"}, "zap": {"status": "TIMEOUT", "reason": "wall-clock"},
             "sqlmap": {"status": "NOT_TESTED", "reason": "no eligible request"}}
    state, reason = external_stage_status(tools, ("nuclei", "zap", "sqlmap"))
    assert state == "partial" and "zap" in reason
    assert web_terminal_status("completed", tools, None) == "partial"
    assert web_terminal_status("completed", {"nuclei": {"status": "COMPLETED"}}, {"status": "FAILED"}) == "partial"
    assert web_terminal_status("completed", {"nuclei": {"status": "COMPLETED"}}, None) == "completed"
    assert web_terminal_status("completed", {"nuclei": {"status": "SKIPPED", "reason": "tool disabled"}}, None) == "partial"


@pytest.mark.asyncio
async def test_per_phase_request_budget_counts_concurrent_tasks():
    from app.core.request_budget import RequestBudget, RequestBudgetExceeded
    budget = RequestBudget(100, 100, 8)
    async def reserve():
        await budget.acquire()
        budget.release()
    with budget.phase_limit(3) as phase:
        result = await asyncio.gather(*(reserve() for _ in range(8)), return_exceptions=True)
    assert phase.used == 3
    assert sum(isinstance(x, RequestBudgetExceeded) for x in result) == 5
    assert budget.used == 3
    await budget.acquire()
    budget.release()
    assert budget.used == 4  # a later phase has independent allowance


def test_endpoint_matrix_never_equates_discovery_with_verified_security_testing():
    from app.core.scan_coverage import build_endpoint_matrix
    web = SimpleNamespace(endpoints=[SimpleNamespace(url="https://example.com/items?id=1", method="GET", status_code=200,
                                                     parameters=["id"])],
                          vulnerability_checks=[])
    api = SimpleNamespace(endpoints=[])
    matrix = build_endpoint_matrix(web, api)
    assert len(matrix) == 1
    assert matrix[0]["security_state"] == "NOT_TESTED"
    assert "no recorded" in matrix[0]["reason"]
    web.vulnerability_checks = [SimpleNamespace(url="https://example.com/items?id=1", method="GET", tested_parameter="id")]
    tested = build_endpoint_matrix(web, api)
    assert tested[0]["security_state"] == "TESTED"


def test_observations_have_explicit_assessment_states():
    blocked = complete_proof(independent_verification=None)
    false_positive = finding(finding_id="no", verification_status="FALSE_POSITIVE")
    skipped = finding(finding_id="skip", verification_status="NOT_APPLICABLE")
    inconclusive = finding(finding_id="uncertain", verification_status="DETECTED")
    apply_confirmation_gate([blocked, false_positive, skipped, inconclusive])
    assert blocked.assessment_state == "LIKELY"
    assert false_positive.assessment_state == "FALSE_POSITIVE"
    assert skipped.assessment_state == "NOT_TESTED"
    assert inconclusive.assessment_state == "INCONCLUSIVE"


def test_missing_csp_or_cors_header_is_hardening_not_vulnerability():
    f = complete_proof(rule_id="WEB-HEADER-CONFIG-CSP", source_module="web", severity="Medium",
                       security_impact=None, independent_verification=None)
    apply_confirmation_gate([f])
    assert f.category == "hardening-observation"
    assert f.assessment_state == "CONFIRMED"
    assert bundle_score(correlate([f])) == 0.0


def test_fingerprint_groups_same_route_without_leaking_query_values():
    from app.modules.correlator.correlator import finding_fingerprint
    a = finding(source_module="zap", affected_asset="https://EXAMPLE.com/orders/125?id=topsecret", method="GET")
    b = finding(source_module="zap", affected_asset="https://example.com/orders/999?id=different", method="GET")
    c = finding(source_module="zap", affected_asset="https://example.com/orders/999?id=different", method="POST")
    assert finding_fingerprint(a) == finding_fingerprint(b)
    assert finding_fingerprint(a) != finding_fingerprint(c)


def test_versioned_ground_truth_metrics_do_not_invent_detection():
    from app.core.ground_truth import evaluate_ground_truth
    target = "https://lab.example:3000"
    f = complete_proof(affected_asset=target + "/rest/user/login", method="POST", parameter="email")
    apply_confirmation_gate([f])
    s = snapshot([f])
    s.coverage.endpoint_matrix = [
        {"url": target + "/rest/user/login", "method": "POST", "security_state": "TESTED"},
        {"url": target + "/api/basket", "method": "GET", "security_state": "NOT_TESTED",
         "reason": "no authenticated session"},
        {"url": target + "/safe", "method": "GET", "security_state": "TESTED"},
    ]
    manifest = {"lab": "OWASP Juice Shop", "version": "TEST-FIXTURE-ONLY",
                "positive_scenarios": [
                    {"id": "positive-login", "rule_id": "SQLI-1", "path": "/rest/user/login", "method": "POST", "parameter": "email"},
                    {"id": "positive-other", "rule_id": "IDOR-1", "path": "/api/basket", "method": "GET"},
                ],
                "negative_scenarios": [
                    {"id": "negative-fake", "rule_id": "XSS-1", "path": "/safe", "method": "GET"},
                ]}
    result = evaluate_ground_truth(s, manifest)
    assert result["lab_version"] == "TEST-FIXTURE-ONLY"
    assert result["precision"] == 1.0
    assert result["recall"] == 0.5
    assert result["false_positive_rate"] == 0.0
    assert result["endpoint_coverage"] == pytest.approx(2 / 3, abs=1e-4)
    assert result["evidence_completeness"] == 1.0
    assert result["uncovered_scenarios"] == ["positive-other"]
    assert result["skipped_endpoints"][0]["reason"] == "no authenticated session"
    s.findings[0].confirmation_state = "CANDIDATE"
    result2 = evaluate_ground_truth(s, manifest)
    assert result2["recall"] == 0
    assert result2["precision"] is None


def test_ground_truth_requires_version_and_nonempty_scenario_ids():
    from app.core.ground_truth import evaluate_ground_truth
    with pytest.raises(ValueError, match="version"):
        evaluate_ground_truth(snapshot([]), {"lab": "OWASP Juice Shop", "positive_scenarios": []})
    with pytest.raises(ValueError, match="unique"):
        evaluate_ground_truth(snapshot([]), {"lab": "OWASP Juice Shop", "version": "x", "positive_scenarios": [
            {"id": "same", "rule_id": "x", "path": "/a"},
            {"id": "same", "rule_id": "y", "path": "/b"},
        ]})


def test_report_does_not_imply_candidate_risks_are_confirmed():
    s = snapshot([finding()])
    from app.modules.reporting.exporters import to_html, to_pdf
    html = to_html(s, language="en", audience="managerial")
    assert "Confirmed: 0" in html
    assert "Candidates: 1" in html
    pdf = to_pdf(s, language="en", audience="managerial")
    assert pdf.startswith(b"%PDF")


def test_confirmation_gate_outcome_makes_verification_and_scan_partial():
    from app.core.scan_health import verification_stage_status, subdomain_assessment_status
    assert verification_stage_status("COMPLETED", {"confirmed": 2, "candidates": 1}) == "PARTIAL"
    assert verification_stage_status("COMPLETED", {"confirmed": 2, "candidates": 0}) == "COMPLETED"
    assert verification_stage_status("FAILED", {"confirmed": 0, "candidates": 1}) == "FAILED"
    assert subdomain_assessment_status([{"status": "SCANNED", "tests": {"dns_verification": "FAILED", "web": "COMPLETED"}}]) == "PARTIAL"
    assert subdomain_assessment_status([{"status": "FAILED", "reason": "timeout", "tests": {"web": "FAILED"}}]) == "FAILED"
    assert subdomain_assessment_status([{"status": "SKIPPED_SCOPE", "reason": "scope guard"}]) == "PARTIAL"
    assert subdomain_assessment_status([{"status": "SCANNED", "tests": {"web": "COMPLETED"}}]) == "COMPLETED"


def test_claimed_independent_proof_and_unparseable_http_evidence_are_not_confirmation():
    for override, reason in [
        ({"independent_verification": "yes"}, "missing_independent_verification"),
        ({"request": "request sent"}, "invalid_reproducible_request"),
        ({"response": "error page"}, "invalid_reproducible_response"),
        ({"verification_timestamp": "yesterday"}, "invalid_verification_timestamp"),
        ({"tool_version": None}, "missing_tool_version"),
    ]:
        f = complete_proof(**override)
        apply_confirmation_gate([f])
        assert f.confirmation_state == "CANDIDATE"
        assert reason in f.confirmation_reason


def test_report_states_negative_results_are_scoped():
    """A missing finding must read as 'not proven within covered scope', never 'absent'."""
    scan = snapshot([])
    for lang, needle in (("en", "not proven within the covered"), ("ar", "لم تُثبت ضمن نقاط النهاية والمعاملات المغطاة")):
        assert needle in generate_markdown(scan, language=lang)
