"""Rich local end-to-end fixture for the Source Intelligence layer.

test_real_target_local_e2e.py is a minimal generic pipeline smoke test (one
near-empty HTML page) that pre-dates this feature. It proves the pipeline
runs, but it never exercised Source Intelligence, secret detection, source
maps, or GraphQL discovery at all — none of that content exists in its
fixture.

This test builds the single local target the original spec asked for: one
page that carries every marker at once (suspicious developer comment, hidden
form input, fake API key, fake JWT-shaped bearer token, an exposed source
map with sourcesContent, a JS-discovered REST endpoint, a JS-discovered
GraphQL endpoint, a dangerous DOM sink, a manifest + service worker) and
drives it through the real, unmocked chain:

    WebScanEngine (crawl + Playwright, if available)
      -> source_intelligence.engine.analyze_web_source
      -> discovered endpoints fed into the API scanner (not duplicated)
      -> normalizer -> correlator -> risk_engine
      -> UnifiedScanResult.findings

Each assertion below checks that a specific layer actually saw and acted on
a specific marker — not just that the overall scan status is "completed".

This needs the project's real dependencies (fastapi, httpx, sqlalchemy,
pydantic, playwright, ...), which are not necessarily installed in every
review/sandboxed environment this file might be inspected from. Run it for
real with:

    pytest backend/tests/integration/test_source_intelligence_fixture_e2e.py -v

Like test_real_target_local_e2e.py, it is a real HTTP integration test
against a local, operator-controlled target and deliberately relaxes the
SSRF/scope guard for that single local loopback address only.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

_HTML = b"""<!DOCTYPE html>
<html><head>
<title>MIRSAD Source Intelligence E2E Fixture</title>
<meta name="generator" content="MIRSAD-Fixture/1.0">
<link rel="manifest" href="/manifest.json">
<!-- TODO remove /internal/debug before shipping to production -->
</head>
<body>
<a href="/public">public</a>
<form action="/login" method="post">
<input type="hidden" name="csrf_token" value="fixture-csrf-token">
</form>
<script src="/app.js"></script>
</body></html>"""

# Every "secret" below is a clearly-fake, obviously-non-functional fixture
# value used only to verify the detection + redaction pipeline, never a real
# credential.
_APP_JS = b"""
const usersEndpoint = "/api/admin/users";
fetch(usersEndpoint).then(function (r) { return r.json(); });
const graphqlEndpoint = "/graphql";
fetch(graphqlEndpoint, {method: "POST", body: JSON.stringify({query: "{__typename}"})});
const apiKey = "sk_live_FAKE00000000000000000000EXAMPLE";
const authToken = "Bearer FAKE_TOKEN_VALUE_NOT_REAL_1234567890";
const adminJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.FAKE_SIGNATURE_NOT_REAL_1234567890";
document.getElementById("out").innerHTML = window.location.hash;
if ("serviceWorker" in navigator) { navigator.serviceWorker.register("/sw.js"); }
//# sourceMappingURL=app.js.map
"""

_APP_JS_MAP = json.dumps({
    "version": 3,
    "sources": ["src/admin/UserAdminPanel.ts"],
    "names": ["adminSecretToken"],
    "sourcesContent": [
        "const endpoint = \"/api/admin/users\"; "
        "const internalNote = \"TODO: remove hardcoded staging credential before prod\"; "
        "const fakeToken = \"Bearer FAKE_TOKEN_VALUE_NOT_REAL_1234567890\";"
    ],
}).encode()

_MANIFEST = json.dumps({"name": "MIRSAD Fixture", "start_url": "/dashboard"}).encode()
_SW = b"self.addEventListener('install', () => self.skipWaiting());"
_ADMIN_USERS = json.dumps([{"id": 1, "username": "fixture-admin"}]).encode()
_GRAPHQL_GET = json.dumps({"errors": [{"message": "Must provide query string."}]}).encode()
_GRAPHQL_POST = json.dumps({"errors": [{"message": "Introspection disabled in this environment."}]}).encode()
_PUBLIC = b"<html><body>public page</body></html>"
_ROBOTS = b"User-agent: *\nAllow: /\n"


class _FixtureHandler(BaseHTTPRequestHandler):
    _ROUTES_GET = {
        "/": ("text/html", _HTML),
        "/app.js": ("application/javascript", _APP_JS),
        "/app.js.map": ("application/json", _APP_JS_MAP),
        "/manifest.json": ("application/manifest+json", _MANIFEST),
        "/sw.js": ("application/javascript", _SW),
        "/api/admin/users": ("application/json", _ADMIN_USERS),
        "/graphql": ("application/json", _GRAPHQL_GET),
        "/public": ("text/html", _PUBLIC),
        "/robots.txt": ("text/plain", _ROBOTS),
    }

    def _send(self, content_type: str, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        entry = self._ROUTES_GET.get(self.path.split("?", 1)[0])
        if entry:
            self._send(*entry)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path.split("?", 1)[0] == "/graphql":
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._send("application/json", _GRAPHQL_POST)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.mark.asyncio
async def test_source_intelligence_full_pipeline_e2e(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "ALLOW_SSRF_RISK_TARGETS", True)
    monkeypatch.setattr(settings, "ENFORCE_TARGET_SCOPE", False)
    monkeypatch.setattr(settings, "ENABLE_SOURCE_INTELLIGENCE", True)
    monkeypatch.setattr(settings, "ENABLE_SOURCE_MAP_ANALYSIS", True)

    from app.core.database import init_db
    from app.core.architecture.manager import manager
    from app.modules.web_scan.scanner import WebScanEngine
    monkeypatch.setattr(WebScanEngine, "_docker_host_url", staticmethod(lambda url: url))
    from app.schemas.platform import FullScanRequest

    init_db()
    # ThreadingHTTPServer, not plain HTTPServer: the real async web+API scan pipeline
    # fires concurrent requests (crawling, endpoint discovery, source-map fetch). A
    # single-threaded HTTPServer handles one request at a time, so under that concurrent
    # load requests queue/time out and request_budget.py's circuit breaker trips with
    # "target unreachable: circuit open after 8 consecutive connection failures" against
    # a server that is, in fact, up and correctly serving every route.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
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
                web_profile="deep",
                max_pages=10,
                max_depth=2,
            )
        )

        assert result.status == "completed"
        assert result.web_scan is not None
        assert result.web_scan.status.value == "completed", result.web_scan.error_message

        si = result.web_scan.source_intelligence
        assert si.get("status") == "COMPLETED", si

        # 1) suspicious developer comment picked up (context-aware, not a
        #    bare keyword match — see engine.py's comment analyzer)
        assert si.get("html", {}).get("comments")

        # 2) hidden form input discovered
        assert si.get("html", {}).get("hidden_inputs")

        # 3) JS-discovered REST endpoint fed forward as an asset — this is
        #    the "Source Intelligence is an enrichment layer, not a second
        #    scanner" requirement: the endpoint must reach the API scanner's
        #    candidate list, not just sit inside source_intelligence itself.
        js_endpoints = si.get("javascript", {}).get("endpoints", [])
        assert any("/api/admin/users" in e for e in js_endpoints)
        assert any("/api/admin/users" in u for u in result.web_scan.api_candidates)

        # 4) secret candidates found in inline JS, and the raw values never
        #    leak into the result payload (the redaction contract)
        assert si.get("javascript", {}).get("secret_candidates")
        dumped = json.dumps(si)
        assert "FAKE_TOKEN_VALUE_NOT_REAL_1234567890" not in dumped
        assert "sk_live_FAKE00000000000000000000EXAMPLE" not in dumped

        # 5) source map fetched, parsed, flagged as exposing original
        #    source, with its own endpoint/secret extracted — again without
        #    the raw secret text leaking
        assert si.get("source_maps", {}).get("maps_analyzed")
        assert si.get("source_maps", {}).get("exposures")
        assert si.get("source_maps", {}).get("secret_candidates")
        assert any("/api/admin/users" in e for e in si.get("source_maps", {}).get("endpoints", []))

        # 6) manifest + service worker surfaced
        assert si.get("manifests", {}).get("assets")
        assert si.get("service_workers", {}).get("assets") or si.get("service_workers", {}).get("registrations")

        # 7) the GraphQL endpoint referenced only inside JS was independently
        #    discovered by the API scanner (not just noticed by source
        #    intelligence) — proves the endpoint handoff actually drives a
        #    real downstream scan, not just a list of strings
        assert result.web_scan.api_integration.get("graphql_discovered") is True

        # 8) everything above must survive normalization + correlation into
        #    the final unified findings list — this is the point of a shared
        #    fixture instead of testing engine.py in isolation. engine.py
        #    always emits a "Source Map Exposes Original Source" finding
        #    when sourcesContent is present; confirm it reaches the top.
        all_titles = " ".join(str(getattr(f, "title", "")) for f in result.findings)
        assert "Source Map" in all_titles

        assert result.snapshot_metadata is not None
        assert "auth_header" not in result.snapshot_metadata.configuration
    finally:
        server.shutdown()
        server.server_close()
