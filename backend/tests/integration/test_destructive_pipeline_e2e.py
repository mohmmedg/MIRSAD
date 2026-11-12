"""Full ScanManager pipeline in destructive mode against a local lab target.

Regression for: web + API engines aborting with
"destructive mode requires destructive_confirmation=true" because the
confirmation flag was not forwarded by ScanManager, and for the external-engine
start/finish logging that keeps the live log from looking frozen.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import AsyncMock, MagicMock

import pytest


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.startswith("/api/items"):
            self._send(200, json.dumps([{"id": 1, "name": "a"}]), "application/json")
        elif self.path == "/openapi.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                                        "paths": {"/api/items": {"get": {"responses": {"200": {"description": "ok"}}}}}}),
                       "application/json")
        else:
            self._send(200, '<html><head><title>lab</title></head><body>'
                            '<a href="/api/items">items</a><a href="/about">about</a></body></html>', "text/html")

    do_POST = do_PUT = do_DELETE = do_GET

    def log_message(self, *_a):
        pass


@pytest.mark.asyncio
async def test_destructive_mode_with_confirmation_runs_web_and_api(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "ALLOW_SSRF_RISK_TARGETS", True)
    monkeypatch.setattr(settings, "ENFORCE_TARGET_SCOPE", False)

    from app.core.database import init_db
    from app.core.architecture.manager import manager
    from app.modules.web_scan.scanner import WebScanEngine
    from app.schemas.platform import FullScanRequest
    monkeypatch.setattr(WebScanEngine, "_docker_host_url", staticmethod(lambda url: url))

    init_db()
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    logs: list[str] = []
    job = MagicMock()
    job.job_id = "e2e-destructive"
    job.progress = 0
    job.checkpoint = AsyncMock()
    job.log.side_effect = lambda m, *a, **k: logs.append(str(m))
    try:
        result = await manager.run(
            FullScanRequest(
                target=f"http://127.0.0.1:{server.server_port}",
                network=False, web=True, api=True,
                scan_profile="deep", safe_mode="destructive", destructive_confirmation=True,
                max_pages=5, max_depth=1,
            ),
            job=job,
        )
    finally:
        server.shutdown()

    text = "\n".join(logs)
    assert "requires destructive_confirmation" not in text, text
    assert "Web engine failed" not in text, text
    assert "API security engine failed" not in text, text
    assert "Web engine completed" in text, text
    # API assessment runs either inside the web engine (handoff) or as its own step
    states = (result.pipeline or {}).get("states") or {}
    print("MODULE_STATES", states)
    assert "API security engine completed" in text or states.get("api") == "COMPLETED", (states, text)
    # every external engine must announce start and finish (no silent multi-minute gaps)
    for label in ("Nuclei external scan", "ZAP external scan", "SQLMap external scan", "ffuf content discovery"):
        assert f"{label} started" in text, text
        assert f"{label} finished" in text, text
    assert result.status in {"completed", "partial"}
