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
