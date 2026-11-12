"""Read-only live verification tests. This file can be run directly when the full DB fixture is unavailable."""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.modules.normalizer.normalizer import verify_findings_live
from app.schemas.platform import NormalizedFinding

class _Lab(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://mirsad.invalid")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Server", "MIRSAD-LAB")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *_args):
        pass

def test_cors_live_replay_verifies_read_only():
    server = HTTPServer(("127.0.0.1", 0), _Lab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        finding = NormalizedFinding(
            finding_id="live-test",
            source_module="web",
            rule_id="WEB-CORS-CONFIG",
            title="CORS configuration observation",
            affected_asset=url,
            verification_status="DETECTED",
        )
        summary = asyncio.run(verify_findings_live([finding]))
        assert finding.verification_status == "VERIFIED"
        assert summary["live_verified"] == 1
    finally:
        server.shutdown()
