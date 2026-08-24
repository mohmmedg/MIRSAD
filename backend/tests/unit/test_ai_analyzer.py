"""
tests/unit/test_ai_analyzer.py

اختبارات AIAnalyzer بدون أي استدعاء فعلي لـ Gemini API — كل استدعاء
للـ Gemini async client client مُموَّه (mocked) بالكامل. بما إن GEMINI_API_KEY
فاضي بيئة الاختبار، القسم الأول من الاختبارات يتحقق من رفض واضح
(AIAnalyzerConfigError)، والقسم الثاني يحقن client مموَّه يدوياً للتحقق من
منطق الـ parsing نفسه.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.modules.ai_analysis.analyzer import (
    AIAnalyzer,
    AIAnalyzerConfigError,
    AIAnalyzerResponseError,
)


@pytest.fixture
def analyzer_no_key():
    """بما إن GEMINI_API_KEY فاضي ببيئة الاختبار (conftest)، هذا الـ
    analyzer عنده client=None فعلياً — يحاكي بالضبط بيئة تطوير بدون مفتاح."""
    return AIAnalyzer()


def _fake_message(text: str):
    return SimpleNamespace(text=text)


class TestConfigValidation:
    @pytest.mark.asyncio
    async def test_raises_config_error_without_api_key(self, analyzer_no_key, sample_network_scan_completed):
        with pytest.raises(AIAnalyzerConfigError):
            await analyzer_no_key.analyze(network_result=sample_network_scan_completed)

    @pytest.mark.asyncio
    async def test_raises_value_error_without_any_scan_result(self, analyzer_no_key):
        with pytest.raises(ValueError):
            await analyzer_no_key.analyze(network_result=None, web_result=None)

    @pytest.mark.asyncio
    async def test_empty_candidates_returns_empty_report_without_calling_api(self):
        """لو نتيجة الفحص completed لكن بدون أي بيانات مفيدة (لا منافذ ولا
        os matches)، ما لازم نستدعي Gemini أصلاً."""
        from datetime import datetime, timezone

        from app.schemas.network import NetworkScanResult, ScanStatus

        empty_result = NetworkScanResult(
            scan_id="x",
            target="127.0.0.1",
            scan_type="basic",
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            open_ports=[],
            os_matches=[],
        )
        analyzer = AIAnalyzer()
        report = await analyzer.analyze(network_result=empty_result)
        assert report.total_findings == 0
        assert report.model_used is None


class TestCandidateBuilding:
    def test_builds_candidate_per_open_port(self, analyzer_no_key, sample_network_scan_completed):
        candidates = analyzer_no_key._build_candidates(sample_network_scan_completed, None)
        port_candidates = [c for c in candidates if c["raw_type"] == "open_port"]
        assert len(port_candidates) == 2

    def test_builds_candidate_for_missing_header_only(self, analyzer_no_key, sample_web_scan_completed):
        candidates = analyzer_no_key._build_candidates(None, sample_web_scan_completed)
        header_candidates = [c for c in candidates if c["raw_type"] == "missing_security_header"]
        # فقط CSP غايب بالفكستشر (HSTS موجود) — لازم مرشّح واحد فقط
        assert len(header_candidates) == 1


class TestResponseParsing:
    def test_parses_clean_json(self, analyzer_no_key):
        raw = json.dumps({"executive_summary": "ok", "findings": []})
        parsed = analyzer_no_key._parse_json_response(raw)
        assert parsed["executive_summary"] == "ok"

    def test_strips_markdown_fences(self, analyzer_no_key):
        raw = "```json\n" + json.dumps({"executive_summary": "ok", "findings": []}) + "\n```"
        parsed = analyzer_no_key._parse_json_response(raw)
        assert parsed["executive_summary"] == "ok"

    def test_rejects_invalid_json(self, analyzer_no_key):
        with pytest.raises(AIAnalyzerResponseError):
            analyzer_no_key._parse_json_response("this is not json at all {{{")

    def test_rejects_json_missing_required_fields(self, analyzer_no_key):
        with pytest.raises(AIAnalyzerResponseError):
            analyzer_no_key._parse_json_response(json.dumps({"foo": "bar"}))

    def test_unexpected_severity_falls_back_to_info(self, analyzer_no_key, sample_network_scan_completed):
        parsed = {
            "executive_summary": "test",
            "findings": [
                {
                    "source_module": "network",
                    "title": "weird",
                    "severity": "SuperCritical",  # قيمة غير متوقعة عمداً
                    "description": "d",
                    "remediation": "r",
                }
            ],
        }
        report = analyzer_no_key._build_report(parsed, sample_network_scan_completed, None)
        assert report.findings[0].severity.value == "Info"


class TestFullFlowWithMockedClient:
    @pytest.mark.asyncio
    async def test_successful_analyze_with_mocked_gemini_client(
        self, sample_network_scan_completed
    ):
        analyzer = AIAnalyzer()
        fake_response_json = {
            "executive_summary": "ملخص تجريبي",
            "findings": [
                {
                    "source_module": "network",
                    "title": "FTP غير مشفّر",
                    "severity": "Medium",
                    "description": "وصف",
                    "evidence": "port 21",
                    "remediation": "استخدم SFTP",
                    "affected_asset": "21/tcp",
                }
            ],
        }
        mock_client = SimpleNamespace(
            aio=SimpleNamespace(
                models=SimpleNamespace(
                    generate_content=AsyncMock(return_value=_fake_message(json.dumps(fake_response_json)))
                )
            )
        )
        analyzer._client = mock_client  # حقن client مموَّه مباشرة

        report = await analyzer.analyze(network_result=sample_network_scan_completed)

        assert report.engine == "ai"
        assert report.total_findings == 1
        assert report.findings[0].title == "FTP غير مشفّر"
        mock_client.aio.models.generate_content.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_malformed_api_response_raises_clear_error(self, sample_network_scan_completed):
        analyzer = AIAnalyzer()
        mock_client = SimpleNamespace(
            aio=SimpleNamespace(
                models=SimpleNamespace(
                    generate_content=AsyncMock(return_value=_fake_message("not valid json"))
                )
            )
        )
        analyzer._client = mock_client

        with pytest.raises(AIAnalyzerResponseError):
            await analyzer.analyze(network_result=sample_network_scan_completed)
