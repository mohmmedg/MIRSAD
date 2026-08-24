"""
tests/integration/test_async_scan_and_status.py

اختبارات لمسار background task الجديد: /network/scan/async،
/web/scan/async، وGET /scans/{scan_id}/status. TestClient بـ Starlette
ينفّذ background tasks بشكل متزامن فعلياً بعد إرجاع الاستجابة (ضمن نفس
سياق الطلب)، فيمكننا التحقق من الحالة النهائية مباشرة بعد نداء الـ status
endpoint بدون الحاجة لـ polling loop حقيقي بالاختبار.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>"""


class TestAsyncNetworkScan:
    def test_returns_202_with_scan_id(self, api_key_headers):
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock(return_value=(SAMPLE_NMAP_XML.encode(), b""))
        mock_process.returncode = 0
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)):
            r = client.post(
                "/api/v1/network/scan/async",
                json={"target": "127.0.0.1", "scan_type": "quick"},
                headers=api_key_headers,
            )
        assert r.status_code == 202
        body = r.json()
        assert "scan_id" in body
        assert body["status"] == "pending"

    def test_out_of_scope_target_rejected_immediately_not_as_202(self, api_key_headers):
        """قرار تصميم مهم: هدف خارج النطاق يُرفض فوراً بـ 403 قبل حتى إنشاء
        سجل بالـ store — مو بعد ما يرجع 202 ويفشل بصمت بالخلفية."""
        r = client.post(
            "/api/v1/network/scan/async", json={"target": "8.8.8.8"}, headers=api_key_headers
        )
        assert r.status_code == 403

    def test_status_reflects_completed_result_after_background_task_runs(self, api_key_headers):
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock(return_value=(SAMPLE_NMAP_XML.encode(), b""))
        mock_process.returncode = 0
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)):
            r = client.post(
                "/api/v1/network/scan/async",
                json={"target": "127.0.0.1", "scan_type": "quick"},
                headers=api_key_headers,
            )
        scan_id = r.json()["scan_id"]

        status_r = client.get(f"/api/v1/scans/{scan_id}/status", headers=api_key_headers)
        assert status_r.status_code == 200
        body = status_r.json()
        assert body["status"] == "completed"
        assert body["result"]["target"] == "127.0.0.1"

    def test_status_reflects_failed_when_nmap_missing(self, api_key_headers):
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(side_effect=FileNotFoundError())
        ):
            r = client.post(
                "/api/v1/network/scan/async",
                json={"target": "127.0.0.1", "scan_type": "quick"},
                headers=api_key_headers,
            )
        scan_id = r.json()["scan_id"]
        status_r = client.get(f"/api/v1/scans/{scan_id}/status", headers=api_key_headers)
        body = status_r.json()
        # scanner.scan() نفسه يلتقط FileNotFoundError ويرجع NetworkScanResult
        # بحالة failed (بدل ما يرفع استثناء)، فالنتيجة تكون completed على
        # مستوى الـ background task، لكن status الداخلي بالنتيجة failed
        assert body["status"] == "completed"
        assert body["result"]["status"] == "failed"


class TestScanStatusAuth:
    def test_status_requires_api_key(self):
        r = client.get("/api/v1/scans/some-id/status")
        assert r.status_code == 401


class TestScanStatusNotFound:
    def test_unknown_scan_id_returns_404(self, api_key_headers):
        r = client.get("/api/v1/scans/does-not-exist/status", headers=api_key_headers)
        assert r.status_code == 404


class TestAsyncWebScan:
    def test_returns_202_and_status_completes(self, api_key_headers):
        mock_response = httpx.Response(
            200,
            headers={"Server": "nginx"},
            request=httpx.Request("GET", "https://example.com/"),
        )
        with patch.object(
            httpx.AsyncClient, "get", new=AsyncMock(return_value=mock_response)
        ), patch("app.modules.web_scan.scanner.WebScanner._check_tls", return_value=None):
            r = client.post(
                "/api/v1/web/scan/async",
                json={"target": "https://example.com/"},
                headers=api_key_headers,
            )
        assert r.status_code == 202
        scan_id = r.json()["scan_id"]

        status_r = client.get(f"/api/v1/scans/{scan_id}/status", headers=api_key_headers)
        assert status_r.json()["status"] == "completed"
