from app.core.finding_confirmation import apply_confirmation_gate
from app.modules.correlator.correlator import correlate, finding_fingerprint
from app.schemas.platform import FindingEvidence, NormalizedFinding


def _finding(**overrides):
    values = {
        "finding_id": "f-1", "scan_id": "scan-1", "source_module": "web",
        "rule_id": "WEB-CORS-CONFIG", "title": "CORS", "affected_asset": "https://one.example/a",
        "verification_status": "VERIFIED", "verification_method": "GET-REPLAY-READONLY",
        "verification_timestamp": "2026-11-10T00:00:00+00:00",
        "evidence": [FindingEvidence(source="test", asset="https://one.example/a", evidence="response observed")],
    }
    values.update(overrides)
    return NormalizedFinding(**values)


def test_verified_without_complete_verification_is_demoted_to_candidate():
    finding = _finding(verification_method=None)
    summary = apply_confirmation_gate([finding])
    assert finding.verification_status == "DETECTED"
    assert finding.confirmation_state == "CANDIDATE"
    assert "missing_verification_method" in finding.confirmation_reason
    assert summary["demoted"] == 1


def test_external_confirmation_requires_artifact_and_execution_id():
    finding = _finding(source_module="sqlmap", raw_artifact_id="artifact-1", execution_id=None)
    apply_confirmation_gate([finding])
    assert finding.confirmation_state == "CANDIDATE"
    assert "missing_execution_id" in finding.confirmation_reason
    finding = _finding(source_module="sqlmap", raw_artifact_id="artifact-1", execution_id="exec-1")
    apply_confirmation_gate([finding])
    assert finding.confirmation_state == "CANDIDATE"
    assert "missing_reproducible_request" in finding.confirmation_reason
    assert "missing_or_invalid_artifact_sha256" in finding.confirmation_reason


def test_internal_live_observation_needs_replay_and_canonical_evidence():
    finding = _finding(source_module="web", rule_id="WEB-HEADER-CONFIG-CSP")
    apply_confirmation_gate([finding])
    assert finding.confirmation_state == "CANDIDATE"
    assert finding.category == "hardening-observation"
    assert "missing_raw_artifact" in finding.confirmation_reason


def test_shared_controls_dedupe_per_origin_not_globally():
    a = _finding(finding_id="a", affected_asset="https://one.example/a")
    b = _finding(finding_id="b", affected_asset="https://one.example/b")
    c = _finding(finding_id="c", affected_asset="https://two.example/a")
    assert finding_fingerprint(a) == finding_fingerprint(b)
    assert finding_fingerprint(a) != finding_fingerprint(c)
    assert len(correlate([a, b, c])) == 2
