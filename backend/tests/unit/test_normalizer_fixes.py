"""
tests/unit/test_normalizer_fixes.py

Regression tests for the normalizer.py fixes made to close the gap between
the official pipeline (normalizer.py -> /risk, /findings, PDF export) and
the previously-separate rule_based_analysis engine:

1. An invalid/expired TLS certificate must produce a High finding via the
   official pipeline (it previously only showed up via the on-demand
   rule_based_analysis engine, invisible everywhere else).
2. A default-credentials hit is a behavioural heuristic, not a directly
   confirmed fact, so it must be reported as DETECTED (needs manual
   confirmation), never VERIFIED, even though c.vulnerable is True.
3. A confirmed local-file-inclusion hit must be Critical severity.
"""
from datetime import datetime, timezone

import pytest

from app.modules.normalizer.normalizer import normalize_bundle
from app.schemas.network import ScanStatus
from app.schemas.web import TLSInfo, VulnerabilityCheck, WebScanResult

NOW = datetime.now(timezone.utc)


def _base_web(**overrides) -> WebScanResult:
    defaults = dict(
        scan_id="scan-1",
        target="https://example.test/",
        status=ScanStatus.COMPLETED,
        started_at=NOW,
        finished_at=NOW,
    )
    defaults.update(overrides)
    return WebScanResult(**defaults)


class TestTLSCertificateFinding:
    def test_invalid_certificate_produces_high_finding(self):
        web = _base_web(tls_info=TLSInfo(enabled=True, certificate_valid=False, error="certificate has expired"))
        findings = normalize_bundle(web=web, scan_id="scan-1")
        cert_findings = [f for f in findings if f.rule_id == "WEB-TLS-INVALID-CERT"]
        assert len(cert_findings) == 1
        assert cert_findings[0].severity == "High"
        assert cert_findings[0].verification_status == "VERIFIED"

    def test_valid_certificate_produces_no_finding(self):
        web = _base_web(tls_info=TLSInfo(enabled=True, certificate_valid=True))
        findings = normalize_bundle(web=web, scan_id="scan-1")
        assert not [f for f in findings if f.rule_id == "WEB-TLS-INVALID-CERT"]

    def test_no_tls_info_does_not_crash(self):
        web = _base_web(tls_info=None)
        findings = normalize_bundle(web=web, scan_id="scan-1")
        assert not [f for f in findings if f.rule_id == "WEB-TLS-INVALID-CERT"]


class TestDefaultCredentialsVerificationLevel:
    def test_default_credentials_hit_is_detected_not_verified(self):
        web = _base_web(vulnerability_checks=[
            VulnerabilityCheck(check_name="default_credentials", tested_parameter="username/password",
                                payload_used="admin:admin", vulnerable=True, evidence="differed from baseline",
                                url="https://example.test/login.jsp", confidence="low"),
        ])
        findings = normalize_bundle(web=web, scan_id="scan-1")
        matches = [f for f in findings if f.rule_id == "WEB-DEFAULT_CREDENTIALS"]
        assert len(matches) == 1
        assert matches[0].verification_status == "DETECTED", "a behavioural heuristic must never be asserted as VERIFIED fact"
        assert matches[0].severity == "High"

    def test_reflected_xss_hit_is_still_verified(self):
        """Sanity check that the DETECTED override is scoped to default_credentials only."""
        web = _base_web(vulnerability_checks=[
            VulnerabilityCheck(check_name="reflected_xss_canary", tested_parameter="q", payload_used="<script>x</script>",
                                vulnerable=True, evidence="reflected", url="https://example.test/search.jsp", confidence="medium"),
        ])
        findings = normalize_bundle(web=web, scan_id="scan-1")
        matches = [f for f in findings if f.rule_id == "WEB-REFLECTED_XSS_CANARY"]
        assert matches[0].verification_status == "VERIFIED"


class TestLFISeverity:
    def test_confirmed_lfi_is_critical(self):
        web = _base_web(vulnerability_checks=[
            VulnerabilityCheck(check_name="local_file_inclusion", tested_parameter="content",
                                payload_used="../../../../../../etc/passwd", vulnerable=True,
                                evidence="Response body contains known file-content signature",
                                url="https://example.test/index.jsp?content=x", confidence="medium"),
        ])
        findings = normalize_bundle(web=web, scan_id="scan-1")
        matches = [f for f in findings if f.rule_id == "WEB-LOCAL_FILE_INCLUSION"]
        assert len(matches) == 1
        assert matches[0].severity == "Critical"
