import json
import pytest

from app.core.request_budget import RequestBudget
from app.modules.source_intelligence.engine import analyze_web_source


class FakeResponse:
    def __init__(self, body, status=200, content_type="application/json"):
        self.content = body.encode()
        self.status_code = status
        self.headers = {"content-type": content_type}

class FakeClient:
    async def get(self, url, follow_redirects=False):
        if url.endswith(".map"):
            return FakeResponse(json.dumps({
                "version": 3,
                "sources": ["src/admin.ts"],
                "names": ["admin"],
                # Must match the "Generic secret assignment" regex (engine.py _SECRET_PATTERNS):
                # key token immediately followed by =/: then a QUOTED value - i.e. api_key="...".
                # The previous fixture, api_key=not-a-real-secret wrapped as one JS string
                # literal (fake="api_key=not-a-real-secret"), put the quote before "api_key"
                # instead of around the value after it, so it could never match that regex.
                "sourcesContent": ['const endpoint="/api/admin/users"; const api_key="not-a-real-secret-123";']
            }), 200)
        if url.endswith(".css"):
            return FakeResponse("/* TODO internal */ .x{background:url('/img/a.png')}", 200, "text/css")
        if url.endswith("manifest.json"):
            return FakeResponse('{"name":"MIRSAD","start_url":"/dashboard"}', 200, "application/manifest+json")
        if url.endswith("sw.js"):
            # engine.py:486 skips any passive asset with status_code>=400 before it ever
            # reaches the service-worker classification at line 509-511 - the previous
            # fixture had no case for sw.js, so it fell through to the 404 default below.
            return FakeResponse('self.addEventListener("fetch", () => fetch("/api/sw/sync"));', 200, "application/javascript")
        return FakeResponse("{}", 404)


@pytest.mark.asyncio
async def test_source_intelligence_context_and_redaction():
    html = """<!-- TODO remove /internal/debug -->
    <form><input type="hidden" name="csrf" value="fake"></form>
    <link rel="stylesheet" href="/app.css"><link rel="manifest" href="/manifest.json">
    <script src="/app.js"></script>
    <script>fetch("/api/admin/users"); const x="api_key='not-real-secret-value'"; navigator.serviceWorker.register("/sw.js")</script>"""
    # "example.test" is not in this suite's ALLOWED_TARGETS (conftest.py only allow-lists
    # example.com among RFC 2606 reserved domains); verify_target_in_scope() inside
    # analyze_web_source()'s source-map fetch rejected it with ScopeViolationError, silently
    # recorded as a warning (by design) and skipped — leaving maps_analyzed empty. Use the
    # allowed reserved domain instead so the source-map path under test actually runs.
    js = ('https://example.com/app.js',
          'const u="/api/v1/users"; const token="Bearer very-secret-token-value"; element.innerHTML = value; //# sourceMappingURL=app.js.map')
    result = await analyze_web_source(
        client=FakeClient(), base_url="https://example.com/",
        html_pages=[("https://example.com/", html)],
        js_bodies=[js], headers={"server":"nginx"}, budget=RequestBudget(max_requests=100),
        run_detectors=False,
    )
    assert result["status"] == "COMPLETED"
    assert result["html"]["hidden_inputs"]
    assert any("/api/v1/users" in x for x in result["javascript"]["endpoints"])
    assert result["source_maps"]["maps_analyzed"]
    assert result["source_maps"]["secret_candidates"]
    assert all("very-secret-token-value" not in json.dumps(result) for _ in [0])
    assert result["css"]["assets"]
    assert result["manifests"]["assets"]
    assert result["service_workers"]["assets"] or result["service_workers"]["registrations"]
    assert result["findings"]
