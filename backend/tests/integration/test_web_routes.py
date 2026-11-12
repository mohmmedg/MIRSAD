"""
tests/integration/test_web_routes.py

اختبارات تكامل على POST /api/v1/web/scan.
"""

from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestAuth:
    def test_missing_api_key_returns_401(self):
        r = client.post("/api/v1/web/scan", json={"target": "https://example.com"})
        assert r.status_code == 401


class TestScopeGuard:
    def test_out_of_scope_hostname_returns_403(self, api_key_headers):
        r = client.post(
            "/api/v1/web/scan",
            json={"target": "https://not-allowed-domain.com"},
            headers=api_key_headers,
        )
        assert r.status_code == 403

    def test_invalid_url_returns_400(self, api_key_headers):
        r = client.post(
            "/api/v1/web/scan", json={"target": "definitely-not-a-url"}, headers=api_key_headers
        )
        assert r.status_code == 400


class TestSuccessfulScan:
    def test_scan_result_shape(self, api_key_headers):
        mock_response = httpx.Response(
            200,
            headers={"Server": "nginx"},
            request=httpx.Request("GET", "https://example.com/"),
        )
        with patch.object(
            httpx.AsyncClient, "request", new=AsyncMock(return_value=mock_response)
        ), patch(
            "app.modules.web_scan.scanner.WebScanEngine._check_tls", return_value=None
        ), patch(
            "app.core.config.check_ssrf_risk", return_value=None
        ):
            r = client.post(
                "/api/v1/web/scan",
                json={"target": "https://example.com/"},
                headers=api_key_headers,
            )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "completed"
        assert body["server_header"] == "nginx"
