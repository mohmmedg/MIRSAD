"""
tests/unit/test_rule_based_analyzer.py

اختبارات RuleBasedAnalyzer — منطق حتمي بالكامل، بدون أي mocking مطلوب
(لا استدعاءات شبكة ولا API خارجي أصلاً بهذا المحرّك).
"""

import pytest

from app.modules.rule_based_analysis.analyzer import RuleBasedAnalyzer
from app.schemas.analysis import Severity


@pytest.fixture
def analyzer():
    return RuleBasedAnalyzer()


class TestNetworkAnalysis:
    def test_known_cve_version_match_produces_finding(self, analyzer, sample_network_scan_completed):
        """vsftpd 2.3.4 بالفكستشر مطابق لقاعدة CVE معروفة بـ rules.py."""
        report = analyzer.analyze(network_result=sample_network_scan_completed)
        titles = [f.title for f in report.findings]
        assert any("vsftpd" in t.lower() or "ftp" in t.lower() for t in titles)

    def test_risky_port_without_cve_match_still_flagged(self, sample_network_scan_completed):
        # منفذ 21 هون له تطابق CVE دقيق، فلنتأكد أن قاعدة risky_port العامة
        # ما تتكرر فوقه (تجنّب ازدواجية بالـ findings لنفس المنفذ)
        analyzer = RuleBasedAnalyzer()
        report = analyzer.analyze(network_result=sample_network_scan_completed)
        port_21_findings = [f for f in report.findings if f.affected_asset == "21/tcp"]
        assert len(port_21_findings) == 1  # مو مكرر

    def test_deterministic_output_same_input_same_result(self, analyzer, sample_network_scan_completed):
        report1 = analyzer.analyze(network_result=sample_network_scan_completed)
        report2 = analyzer.analyze(network_result=sample_network_scan_completed)
        assert report1.total_findings == report2.total_findings
        assert report1.severity_counts == report2.severity_counts

    def test_different_version_does_not_match_cve_rule(self, analyzer, sample_network_scan_completed):
        """نفس المنتج بإصدار مختلف عن القاعدة المحددة يجب ألا يُصنَّف Critical
        تلقائياً — تأكيد دقة المطابقة (مو تعميم خاطئ)."""
        sample_network_scan_completed.open_ports[1].version = "3.0.5"  # مو 2.3.4
        report = analyzer.analyze(network_result=sample_network_scan_completed)
        port_21 = next(f for f in report.findings if f.affected_asset == "21/tcp")
        assert port_21.severity != Severity.CRITICAL

    def test_requires_at_least_one_scan_result(self, analyzer):
        with pytest.raises(ValueError):
            analyzer.analyze(network_result=None, web_result=None)

    def test_failed_scan_produces_no_findings(self, analyzer):
        from datetime import datetime, timezone

        from app.schemas.network import NetworkScanResult, ScanStatus

        failed = NetworkScanResult(
            scan_id="x",
            target="127.0.0.1",
            scan_type="basic",
            status=ScanStatus.FAILED,
            started_at=datetime.now(timezone.utc),
            error_message="timeout",
        )
        report = analyzer.analyze(network_result=failed)
        assert report.total_findings == 0


class TestWebAnalysis:
    def test_missing_security_header_flagged(self, analyzer, sample_web_scan_completed):
        report = analyzer.analyze(web_result=sample_web_scan_completed)
        titles = [f.title for f in report.findings]
        assert any("Content-Security-Policy" in t for t in titles)

    def test_present_header_not_flagged(self, analyzer, sample_web_scan_completed):
        report = analyzer.analyze(web_result=sample_web_scan_completed)
        titles = [f.title for f in report.findings]
        assert not any("Strict-Transport-Security" in t for t in titles)

    def test_server_header_disclosure_flagged_as_low(self, analyzer, sample_web_scan_completed):
        report = analyzer.analyze(web_result=sample_web_scan_completed)
        server_finding = next(f for f in report.findings if "Server" in f.title)
        assert server_finding.severity == Severity.LOW

    def test_missing_tls_flagged_high(self, analyzer, sample_web_scan_completed):
        from app.schemas.web import TLSInfo

        sample_web_scan_completed.tls_info = TLSInfo(enabled=False, error="not https")
        report = analyzer.analyze(web_result=sample_web_scan_completed)
        tls_finding = next(f for f in report.findings if "TLS" in f.title or "HTTPS" in f.title)
        assert tls_finding.severity == Severity.HIGH

    def test_vulnerable_xss_check_produces_critical_finding(self, analyzer, sample_web_scan_completed):
        from app.schemas.web import VulnerabilityCheck

        sample_web_scan_completed.vulnerability_checks = [
            VulnerabilityCheck(
                check_name="reflected_xss_basic",
                tested_parameter="q",
                vulnerable=True,
                evidence="payload reflected unescaped",
            )
        ]
        report = analyzer.analyze(web_result=sample_web_scan_completed)
        xss_findings = [f for f in report.findings if "xss" in (f.evidence or "").lower() or f.affected_asset == "parameter: q"]
        assert len(xss_findings) == 1
        assert xss_findings[0].severity == Severity.CRITICAL


class TestBothEngines:
    def test_combined_network_and_web_findings(self, analyzer, sample_network_scan_completed, sample_web_scan_completed):
        report = analyzer.analyze(
            network_result=sample_network_scan_completed, web_result=sample_web_scan_completed
        )
        sources = {f.source_module for f in report.findings}
        assert "network" in sources
        assert "web" in sources

    def test_report_id_unique_across_calls(self, analyzer, sample_network_scan_completed):
        report1 = analyzer.analyze(network_result=sample_network_scan_completed)
        report2 = analyzer.analyze(network_result=sample_network_scan_completed)
        assert report1.report_id != report2.report_id
