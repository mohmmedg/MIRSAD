from datetime import datetime, timezone
from types import SimpleNamespace

from app.modules.normalizer.normalizer import normalize_bundle, verify_findings
from app.schemas.web import HeaderCheck, WebScanResult
from app.modules.correlator.correlator import correlate
from app.modules.reporting.generator import generate_markdown


def test_verification_is_finding_level_not_raw_presence():
    w = WebScanResult(
        scan_id="s", target="https://example.com", status="completed",
        started_at=datetime.now(timezone.utc), finished_at=datetime.now(timezone.utc),
        content_type="text/html", endpoints_count=3,
        security_headers=[HeaderCheck(header_name="Content-Security-Policy", present=False)],
        passive_findings=["Server header exposes Apache/2"],
    )
    findings = normalize_bundle(web=w, scan_id="s")
    summary = verify_findings(findings)
    assert summary["findings_total"] == 2
    assert summary["verified"] == 1
    assert summary["detected"] == 1
    assert summary["state"] == "PARTIAL"


def test_header_severity_is_contextual():
    public = WebScanResult(scan_id="s", target="https://example.com", status="completed", started_at=datetime.now(timezone.utc), content_type="application/json", endpoints_count=0, security_headers=[HeaderCheck(header_name="Content-Security-Policy", present=False)])
    app = WebScanResult(scan_id="s", target="https://example.com", status="completed", started_at=datetime.now(timezone.utc), content_type="text/html", endpoints_count=5, security_headers=[HeaderCheck(header_name="Content-Security-Policy", present=False)])
    assert normalize_bundle(web=public)[0].severity == "Low"
    assert normalize_bundle(web=app)[0].severity == "Medium"


def test_attack_surface_is_hierarchical_in_report():
    from app.schemas.platform import UnifiedScanResult
    s = UnifiedScanResult(scan_id="s", target="https://example.com", normalized_target="https://example.com", status="completed", started_at=datetime.now(timezone.utc), assets=[{"ips":["1.2.3.4"],"services":["https:443"],"technologies":["nginx"]}], technologies=["nginx"], pipeline={"states":{}})
    text = generate_markdown(s, "en")
    assert "Domain: https://example.com" in text and "IP: 1.2.3.4" in text and "Service: https:443" in text and "Technology: nginx" in text
