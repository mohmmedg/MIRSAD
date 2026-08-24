"""
tests/integration/test_analysis_routes.py

اختبارات تكامل على /api/v1/analysis/* — rule-based (بدون API key خارجي)،
AI (يرجع خطأ واضح بدون GEMINI_API_KEY)، والتقارير حسب الجمهور، وCVE
lookup الحي عبر NVD (مموَّه بالكامل).
"""

from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.modules.rule_based_analysis.nvd_client import _cache_path

client = TestClient(app)


def _network_payload(sample_network_scan_completed):
    return {"network_scan": sample_network_scan_completed.model_dump(mode="json")}


class TestAuth:
    def test_missing_api_key_returns_401(self, sample_network_scan_completed):
        r = client.post(
            "/api/v1/analysis/rule-based/run", json=_network_payload(sample_network_scan_completed)
        )
        assert r.status_code == 401


class TestRuleBasedRun:
    def test_returns_analysis_report(self, api_key_headers, sample_network_scan_completed):
        r = client.post(
            "/api/v1/analysis/rule-based/run",
            json=_network_payload(sample_network_scan_completed),
            headers=api_key_headers,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["engine"] == "rule_based"
        assert body["total_findings"] > 0

    def test_requires_at_least_one_scan(self, api_key_headers):
        r = client.post(
            "/api/v1/analysis/rule-based/run", json={}, headers=api_key_headers
        )
        assert r.status_code == 400


class TestAIRun:
    def test_returns_502_or_500_without_api_key(self, api_key_headers, sample_network_scan_completed):
        """بدون GEMINI_API_KEY (بيئة الاختبار)، لازم رفض واضح مش خطأ غامض."""
        r = client.post(
            "/api/v1/analysis/run",
            json=_network_payload(sample_network_scan_completed),
            headers=api_key_headers,
        )
        assert r.status_code == 500
        assert "GEMINI_API_KEY" in r.json()["detail"]


class TestCompare:
    def test_compare_always_returns_rule_based_even_if_ai_fails(
        self, api_key_headers, sample_network_scan_completed
    ):
        r = client.post(
            "/api/v1/analysis/compare",
            json=_network_payload(sample_network_scan_completed),
            headers=api_key_headers,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["rule_based_report"] is not None
        assert body["ai_report"] is None
        assert body["ai_error"] is not None


class TestCVELookup:
    def test_requires_api_key(self):
        r = client.post("/api/v1/analysis/cve-lookup", json={"product": "nginx", "version": "1.0"})
        assert r.status_code == 401

    def test_successful_lookup(self, api_key_headers):
        mock_response = httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2011-2523",
                            "descriptions": [{"lang": "en", "value": "test desc"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                ]
                            },
                            "published": "2011-07-04T00:00:00.000",
                        }
                    }
                ]
            },
            request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        )
        if _cache_path().exists():
            _cache_path().unlink()

        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_response)):
            r = client.post(
                "/api/v1/analysis/cve-lookup",
                json={"product": "vsftpd", "version": "2.3.4"},
                headers=api_key_headers,
            )
        assert r.status_code == 200
        body = r.json()
        assert body["results"][0]["cve_id"] == "CVE-2011-2523"

    def test_nvd_failure_returns_503(self, api_key_headers):
        if _cache_path().exists():
            _cache_path().unlink()

        with patch.object(
            httpx.AsyncClient, "get", new=AsyncMock(side_effect=httpx.ConnectTimeout("x"))
        ):
            r = client.post(
                "/api/v1/analysis/cve-lookup",
                json={"product": "some-unique-product-xyz", "version": "1.2.3"},
                headers=api_key_headers,
            )
        assert r.status_code == 503


class TestAudienceReports:
    def test_report_all_returns_three_audiences(self, api_key_headers, sample_network_scan_completed):
        r = client.post(
            "/api/v1/analysis/rule-based/report/all",
            json=_network_payload(sample_network_scan_completed),
            headers=api_key_headers,
        )
        assert r.status_code == 200
        body = r.json()
        assert set(body.keys()) == {"technical", "managerial", "non_technical"}

    def test_single_audience_report(self, api_key_headers, sample_network_scan_completed):
        payload = _network_payload(sample_network_scan_completed)
        payload["audience"] = "non_technical"
        r = client.post(
            "/api/v1/analysis/rule-based/report", json=payload, headers=api_key_headers
        )
        assert r.status_code == 200
        assert r.json()["audience"] == "non_technical"
