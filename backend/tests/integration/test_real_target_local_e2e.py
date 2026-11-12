"""Real HTTP integration gate against an operator-controlled local target.

This is deliberately opt-in because it relaxes the SSRF guard for a local lab
server. It exercises the actual WebScanner + API handoff + normalization +
verification + correlation + risk + immutable snapshot path.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            b'<html><head><title>MIRSAD local target</title></head>'
            b'<body><a href="/public">public</a></body></html>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.mark.asyncio
async def test_real_local_http_scan_end_to_end(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "ALLOW_SSRF_RISK_TARGETS", True)
    monkeypatch.setattr(settings, "ENFORCE_TARGET_SCOPE", False)

    from app.core.database import init_db
    from app.core.architecture.manager import manager
    from app.modules.web_scan.scanner import WebScanEngine
    monkeypatch.setattr(WebScanEngine, "_docker_host_url", staticmethod(lambda url: url))
    from app.schemas.platform import FullScanRequest

    init_db()
    server = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        result = await manager.run(
            FullScanRequest(
                target=f"http://127.0.0.1:{port}",
                network=False,
                web=True,
                api=True,
                web_profile="quick",
                max_pages=5,
                max_depth=1,
            )
        )
        assert result.status == "completed"
        assert result.snapshot_version == "2"
        assert result.web_scan is not None
        assert result.web_scan.status.value == "completed", result.web_scan.error_message
        assert result.coverage.capabilities["http"]["status"] == "COMPLETED"
        assert result.pipeline["states"]["verification"] in {"COMPLETED", "PARTIAL"}
        assert result.verification_summary["state"] == result.pipeline["states"]["verification"]
        assert result.snapshot_metadata is not None
        assert "auth_header" not in result.snapshot_metadata.configuration
    finally:
        server.shutdown()
        server.server_close()
