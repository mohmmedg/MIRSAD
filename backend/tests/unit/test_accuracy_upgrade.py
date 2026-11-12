from datetime import datetime, timezone

from app.modules.correlator.correlator import correlate, finding_fingerprint
from app.modules.risk_engine.engine import assess, bundle_score
from app.modules.reporting.exporters import to_json, to_csv, to_pdf
from app.schemas.platform import NormalizedFinding, FindingEvidence, UnifiedScanResult


def make_finding(title="Missing CSP", asset="https://example.test"):
    return NormalizedFinding(
        finding_id="one", source_module="web", rule_id="WEB-HEADER-CSP",
        title=title, severity="Medium", confidence=.9,
        evidence=[FindingEvidence(source="http", asset=asset, evidence="Header Content-Security-Policy: missing")],
        affected_asset=asset,
    )


def test_same_finding_is_deduplicated_by_stable_fingerprint():
    a = make_finding(); b = make_finding(); b.finding_id = "two"
    result = correlate([a, b])
    assert len(result) == 1
    assert result[0].duplicate_count == 2
    assert result[0].fingerprint == finding_fingerprint(a)


def test_risk_is_deterministic_and_verification_matters():
    f = make_finding()
    first = assess(f).score
    second = assess(f).score
    assert first == second
    f.verification_status = "VERIFIED"
    # A scanner saying VERIFIED does not by itself establish a reportable PoC.
    assert assess(f).score == first == 0.0
    f.confirmation_state = "CONFIRMED"  # the independent confirmation gate's output
    assert assess(f).score > first
    assert bundle_score([f]) == bundle_score([f])


def test_report_exports_are_redacted_and_include_scan_id():
    finding = correlate([make_finding()])[0]
    scan = UnifiedScanResult(
        scan_id="scan-123", target="https://example.test", status="completed",
        started_at=datetime.now(timezone.utc), findings=[finding],
    )
    scan.findings[0].evidence[0].evidence = "Authorization: Bearer secret-token"
    payload = to_json(scan)
    assert payload["scan_id"] == "scan-123"
    assert "secret-token" not in str(payload)
    csv = to_csv(scan)
    assert "scan-123" in csv and "secret-token" not in csv
    assert to_pdf(scan).startswith(b"%PDF")


def test_shared_control_finding_never_merges_distinct_hosts():
    a = make_finding(asset="https://one.example"); a.finding_id="f1"
    b = make_finding(asset="https://two.example"); b.finding_id="f2"
    a.rule_id = "WEB-HEADER-CONFIG-CONTENT_SECURITY_POLICY"
    b.rule_id = a.rule_id
    a.title = b.title = "Security header configuration: Content-Security-Policy"
    a.affected_asset = "https://one.example"
    b.affected_asset = "https://two.example"
    result = correlate([a, b])
    assert len(result) == 2
    assert all(x.duplicate_count == 1 for x in result)
    assert {x.affected_asset for x in result} == {"https://one.example", "https://two.example"}
    # Per-origin controls can still deduplicate repeated paths on one host.
    b.affected_asset = "https://one.example/another/page"
    b.fingerprint = ""  # changing an input requires recomputing its cached identity
    assert len(correlate([a, b])) == 1



def test_managerial_json_and_csv_omit_internal_identifiers_and_raw_evidence():
    finding = correlate([make_finding()])[0]
    finding.evidence[0].evidence = "Authorization: Bearer secret-token"
    scan = UnifiedScanResult(
        scan_id="private-scan-id", target="https://example.test", status="completed",
        started_at=datetime.now(timezone.utc), findings=[finding],
    )
    payload = to_json(scan, audience="managerial")
    rendered = str(payload)
    assert "private-scan-id" not in rendered
    assert finding.finding_id not in rendered
    assert finding.fingerprint not in rendered
    assert "evidence" not in rendered.lower()
    csv_text = to_csv(scan, audience="managerial")
    assert "finding_id" not in csv_text.splitlines()[0]
    assert "private-scan-id" not in csv_text
    assert "secret-token" not in csv_text
