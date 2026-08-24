"""
tests/unit/test_nvd_client.py

اختبارات لعميل NVD — بدون أي طلب شبكة حقيقي، كل شي عبر httpx.AsyncClient.get
المموَّه. كل اختبار يستخدم DATA_DIR مؤقت منفصل عشان الكاش ما يتداخل بين
الاختبارات.
"""

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.modules.rule_based_analysis.nvd_client import (
    NVDLookupError,
    _cache_path,
    lookup_cves,
)

SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2011-2523",
                "descriptions": [
                    {"lang": "en", "value": "vsftpd backdoor vulnerability description."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                },
                "published": "2011-07-04T00:00:00.000",
            }
        }
    ]
}


@pytest.fixture(autouse=True)
def _clean_cache():
    cache_file = _cache_path()
    if cache_file.exists():
        cache_file.unlink()
    yield
    if cache_file.exists():
        cache_file.unlink()


class TestLookupCVEs:
    @pytest.mark.asyncio
    async def test_successful_lookup_parses_results(self):
        mock_response = httpx.Response(
            200,
            json=SAMPLE_NVD_RESPONSE,
            request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        )
        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_response)):
            results = await lookup_cves("vsftpd", "2.3.4")

        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2011-2523"
        assert results[0]["cvss_score"] == 9.8
        assert results[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_rejects_empty_product_or_version(self):
        with pytest.raises(ValueError):
            await lookup_cves("", "1.0")
        with pytest.raises(ValueError):
            await lookup_cves("nginx", "")

    @pytest.mark.asyncio
    async def test_network_failure_raises_nvd_lookup_error(self):
        with patch.object(
            httpx.AsyncClient, "get", new=AsyncMock(side_effect=httpx.ConnectTimeout("timeout"))
        ):
            with pytest.raises(NVDLookupError):
                await lookup_cves("nginx", "1.18.0")

    @pytest.mark.asyncio
    async def test_rate_limit_response_raises_clear_error(self):
        mock_response = httpx.Response(
            429, request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        )
        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_response)):
            with pytest.raises(NVDLookupError, match="rate limit"):
                await lookup_cves("nginx", "1.18.0")

    @pytest.mark.asyncio
    async def test_second_call_uses_cache_not_network(self):
        mock_response = httpx.Response(
            200,
            json=SAMPLE_NVD_RESPONSE,
            request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        )
        mock_get = AsyncMock(return_value=mock_response)
        with patch.object(httpx.AsyncClient, "get", new=mock_get):
            await lookup_cves("vsftpd", "2.3.4")
            await lookup_cves("vsftpd", "2.3.4")

        assert mock_get.call_count == 1  # ثاني نداء من الكاش، بدون طلب شبكة

    @pytest.mark.asyncio
    async def test_expired_cache_triggers_new_network_call(self):
        mock_response = httpx.Response(
            200,
            json=SAMPLE_NVD_RESPONSE,
            request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        )
        mock_get = AsyncMock(return_value=mock_response)
        with patch.object(httpx.AsyncClient, "get", new=mock_get):
            await lookup_cves("vsftpd", "2.3.4")

        # نتلاعب بوقت الكاش يدوياً عشان يبدو منتهي الصلاحية
        import json

        with open(_cache_path(), encoding="utf-8") as f:
            cache = json.load(f)
        for entry in cache.values():
            entry["cached_at"] = time.time() - (8 * 24 * 60 * 60)  # قبل 8 أيام
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(cache, f)

        with patch.object(httpx.AsyncClient, "get", new=mock_get):
            await lookup_cves("vsftpd", "2.3.4")

        assert mock_get.call_count == 2  # الكاش منتهي، لازم نداء شبكة جديد

    @pytest.mark.asyncio
    async def test_malformed_response_raises_nvd_lookup_error(self):
        mock_response = httpx.Response(
            200,
            content=b"not valid json {{{",
            request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        )
        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_response)):
            with pytest.raises(NVDLookupError):
                await lookup_cves("nginx", "1.18.0")
