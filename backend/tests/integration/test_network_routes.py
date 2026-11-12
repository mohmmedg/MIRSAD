"""
tests/integration/test_network_routes.py

اختبارات تكامل عبر FastAPI TestClient على POST /api/v1/network/scan —
تغطي المصادقة، Scope Guard، SSRF Guard، والمسار الناجح (مع mocking لـ nmap).
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>"""


class TestAuth:
    def test_missing_api_key_returns_401(self):
        r = client.post("/api/v1/network/scan", json={"target": "127.0.0.1"})
        assert r.status_code == 401

    def test_wrong_api_key_returns_401(self):
        r = client.post(
            "/api/v1/network/scan",
            json={"target": "127.0.0.1"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert r.status_code == 401

    def test_correct_api_key_passes_auth(self, api_key_headers):
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock(return_value=(SAMPLE_NMAP_XML.encode(), b""))
        mock_process.returncode = 0
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)):
            r = client.post(
                "/api/v1/network/scan",
                json={"target": "127.0.0.1", "scan_type": "quick"},
                headers=api_key_headers,
            )
        assert r.status_code == 200


class TestScopeAndSSRF:
    def test_out_of_scope_target_returns_403(self, api_key_headers):
        r = client.post(
            "/api/v1/network/scan", json={"target": "8.8.8.8"}, headers=api_key_headers
        )
        assert r.status_code == 403
        assert "غير مصرّح" in r.json()["detail"]

    def test_ssrf_risk_target_returns_403(self, api_key_headers):
        r = client.post(
            "/api/v1/network/scan",
            json={"target": "169.254.169.254"},
            headers=api_key_headers,
        )
        assert r.status_code == 403
        assert "SSRF" in r.json()["detail"]


class TestValidation:
    def test_invalid_scan_type_returns_400(self, api_key_headers):
        r = client.post(
            "/api/v1/network/scan",
            json={"target": "127.0.0.1", "scan_type": "nonexistent"},
            headers=api_key_headers,
        )
        assert r.status_code == 400

    def test_missing_target_returns_422(self, api_key_headers):
        r = client.post("/api/v1/network/scan", json={}, headers=api_key_headers)
        assert r.status_code == 422


class TestSuccessfulScan:
    def test_scan_result_shape(self, api_key_headers):
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock(return_value=(SAMPLE_NMAP_XML.encode(), b""))
        mock_process.returncode = 0
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)):
            r = client.post(
                "/api/v1/network/scan",
                json={"target": "127.0.0.1", "scan_type": "quick"},
                headers=api_key_headers,
            )
        body = r.json()
        assert body["status"] == "completed"
        assert body["target"] == "127.0.0.1"
        assert len(body["open_ports"]) == 1


class TestHealthCheck:
    def test_health_endpoint_no_auth_required(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
