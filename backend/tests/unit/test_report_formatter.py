"""
tests/unit/test_report_formatter.py

اختبارات ReportFormatter — التأكد أن التقارير الثلاثة (technical/managerial/
non_technical) مبنية من نفس الـ findings بدون تغيير بالتصنيف، وأن
non_technical يستبعد مستوى Info كما هو موثّق بالـ README.
"""

import pytest

from app.modules.rule_based_analysis.analyzer import RuleBasedAnalyzer
from app.modules.rule_based_analysis.report_formatter import ReportFormatter
from app.schemas.analysis import AudienceLevel


@pytest.fixture
def formatter():
    return ReportFormatter()


@pytest.fixture
def report(sample_network_scan_completed):
    return RuleBasedAnalyzer().analyze(network_result=sample_network_scan_completed)


class TestReportFormatter:
    def test_all_three_audiences_produce_output(self, formatter, report):
        for audience in AudienceLevel:
            formatted = formatter.format_report(report, audience)
            assert formatted.body_markdown
            assert formatted.audience == audience

    def test_severity_counts_identical_across_audiences(self, formatter, report):
        technical = formatter.format_report(report, AudienceLevel.TECHNICAL)
        managerial = formatter.format_report(report, AudienceLevel.MANAGERIAL)
        non_technical = formatter.format_report(report, AudienceLevel.NON_TECHNICAL)
        assert technical.severity_counts == managerial.severity_counts == non_technical.severity_counts

    def test_report_id_preserved_across_audiences(self, formatter, report):
        for audience in AudienceLevel:
            formatted = formatter.format_report(report, audience)
            assert formatted.report_id == report.report_id

    def test_non_technical_excludes_info_only_findings(self, formatter):
        """لو كل الـ findings مستوى Info، non_technical لازم يرجع رسالة
        'لا مشاكل' بينما technical/managerial يعرضونها عادي."""
        from datetime import datetime, timezone

        from app.schemas.network import (
            NetworkScanResult,
            PortInfo,
            PortState,
            ScanStatus,
        )

        info_only = NetworkScanResult(
            scan_id="x",
            target="127.0.0.1",
            scan_type="basic",
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            open_ports=[
                PortInfo(port=8080, protocol="tcp", state=PortState.OPEN, service_name="unknown-app")
            ],
            os_matches=[],
        )
        info_report = RuleBasedAnalyzer().analyze(network_result=info_only)
        assert all(f.severity.value == "Info" for f in info_report.findings)

        non_technical = formatter.format_report(info_report, AudienceLevel.NON_TECHNICAL)
        technical = formatter.format_report(info_report, AudienceLevel.TECHNICAL)

        assert "ما لقى" in non_technical.body_markdown or "لا يوجد" in non_technical.body_markdown
        assert str(info_report.total_findings) in technical.body_markdown or technical.total_findings == info_report.total_findings
