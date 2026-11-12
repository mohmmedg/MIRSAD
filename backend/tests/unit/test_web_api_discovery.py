import pytest
from unittest.mock import AsyncMock, patch
import httpx

from app.modules.web_scan.scanner import WebScanner
from app.schemas.network import ScanStatus
from app.schemas.api_security import APISecurityResult
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_openapi_and_graphql_discovery_is_forwarded_to_api_engine():
    scanner = WebScanner()
    response = httpx.Response(
        200,
        text='''<html><a href="/openapi.json">API</a><a href="/graphql">GraphQL</a></html>''',
        headers={"content-type": "text/html"},
        request=httpx.Request("GET", "https://example.com/"),
    )
    fake_api = MagicApiResult()
    with patch.object(httpx.AsyncClient, "request", new=AsyncMock(return_value=response)), \
         patch.object(scanner, "_check_tls", return_value=None), \
         patch.object(scanner, "_run_templates", new=AsyncMock(return_value=([], 0))), \
         patch.object(scanner.api_scanner, "scan", new=AsyncMock(return_value=fake_api)) as api_call, \
         patch("app.core.config.check_ssrf_risk", return_value=None):
        result = await scanner.scan("https://example.com/", profile="deep", max_pages=2, max_depth=1)
    assert result.status == ScanStatus.COMPLETED
    api_call.assert_awaited()


class MagicApiResult(APISecurityResult):
    def __init__(self):
        super().__init__(
            scan_id="fake-api-scan-id",
            target="https://example.com/",
            status=ScanStatus.COMPLETED.value,
            started_at=datetime.now(timezone.utc),
            openapi={"discovered": True},
            graphql={"discovered": True},
        )
