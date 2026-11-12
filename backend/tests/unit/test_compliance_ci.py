from app.modules.compliance import assess, ci_gate, to_sarif

def finding(title="SQL injection", severity="High", tags=None):
    return {"finding_id":"f1","source_module":"web","title":title,"severity":severity,
            "confidence":0.9,"description":"deterministic evidence","evidence":[],"affected_asset":"https://example.test",
            "tags":tags or ["web","active"],"remediation":"fix"}

def test_compliance_assessment_fails_on_high():
    r=assess([finding()])
    assert r["failed"] >= 1
    assert r["score"] < 100

def test_compliance_passes_without_blocking_evidence():
    r=assess([finding("Missing header","Low",["web","headers"])])
    assert r["score"] >= 0
    assert r["controls"]

def test_ci_gate_and_sarif():
    r=ci_gate([finding()],{"critical_fail":0,"high_fail":0,"medium_fail":0})
    assert r["passed"] is False and r["exit_code"] == 1
    assert r["sarif"]["version"]=="2.1.0"
    assert r["sarif"]["runs"][0]["results"]

def test_ci_gate_allows_configured_threshold():
    r=ci_gate([finding()],{"critical_fail":0,"high_fail":1,"medium_fail":0})
    assert r["passed"] is True


class TestCoverageAwareAssessment:
    """RULE 26/74: NOT_TESTED must never look like PASS, and a genuinely tested,
    clean capability must not be stuck at NOT_ASSESSED forever just because there
    happened to be nothing to flag."""

    def test_without_coverage_zero_findings_stays_not_assessed(self):
        r = assess([])
        auth_control = next(c for c in r["controls"] if c["control_id"] == "ASVS-1.2.1")
        assert auth_control["status"] == "not_assessed"

    def test_tested_capability_with_zero_findings_becomes_pass(self):
        coverage = {"capabilities": {"authentication": {"status": "COMPLETED"}}}
        r = assess([], coverage=coverage)
        auth_control = next(c for c in r["controls"] if c["control_id"] == "ASVS-1.2.1")
        assert auth_control["status"] == "pass"

    def test_explicitly_untested_capability_stays_not_assessed_even_with_coverage_present(self):
        coverage = {"capabilities": {"authentication": {"status": "NOT_TESTED", "reason": "No authentication material configured"}}}
        r = assess([], coverage=coverage)
        auth_control = next(c for c in r["controls"] if c["control_id"] == "ASVS-1.2.1")
        assert auth_control["status"] == "not_assessed"

    def test_blocking_finding_wins_over_tested_coverage(self):
        coverage = {"capabilities": {"authentication": {"status": "COMPLETED"}}}
        r = assess([finding("Broken auth", "High", ["auth"])], coverage=coverage)
        auth_control = next(c for c in r["controls"] if c["control_id"] == "ASVS-1.2.1")
        assert auth_control["status"] == "fail"

    def test_control_with_unmapped_tags_ignores_coverage_and_uses_findings_heuristic(self):
        # "CUSTOM-SCOPE-1" only has the "scope" tag, which has no capability mapping.
        coverage = {"capabilities": {"authentication": {"status": "COMPLETED"}}}
        r = assess([], coverage=coverage)
        scope_control = next(c for c in r["controls"] if c["control_id"] == "CUSTOM-SCOPE-1")
        assert scope_control["status"] == "not_assessed"

    def test_partial_capability_state_counts_as_tested(self):
        coverage = {"capabilities": {"web": {"status": "PARTIAL"}}}
        r = assess([], coverage=coverage)
        header_control = next(c for c in r["controls"] if c["control_id"] == "ASVS-14.4.3")
        assert header_control["status"] == "pass"


class TestCIGateCoverageVisibility:
    """RULE 27: a passing gate must not silently imply everything was tested."""

    def test_untested_capabilities_are_surfaced_without_changing_pass_fail(self):
        coverage = {"capabilities": {
            "authentication": {"status": "NOT_TESTED", "reason": "No authentication material configured"},
            "web": {"status": "COMPLETED"},
        }}
        r = ci_gate([], {"critical_fail": 0}, coverage=coverage)
        assert r["passed"] is True
        assert "authentication" in r["untested_capabilities"]
        assert "web" not in r["untested_capabilities"]

    def test_no_coverage_supplied_yields_empty_untested_list_not_an_error(self):
        r = ci_gate([finding()], {"critical_fail": 0, "high_fail": 1})
        assert r["untested_capabilities"] == []
