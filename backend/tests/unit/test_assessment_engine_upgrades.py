import pytest

from app.core.request_budget import RequestBudget, RequestBudgetExceeded
from app.modules.technology.js_analyzer import analyze_js
from app.schemas.platform import FullScanRequest
from app.core.scan_profiles import resolve_profile


@pytest.mark.asyncio
async def test_request_budget_enforces_max_attempts():
    budget = RequestBudget(max_requests=2, requests_per_second=100, max_concurrency=1)
    await budget.acquire(); budget.release()
    await budget.acquire(); budget.release()
    with pytest.raises(RequestBudgetExceeded):
        await budget.acquire()
    assert budget.used == 2


def test_js_analysis_uses_actual_asset_body_pairs():
    result = analyze_js(
        ["https://example.test/app.js"],
        ["fetch('/api/v1/users'); const token = 'not-a-real-secret';"]
    )
    assert "https://example.test/api/v1/users" in result["endpoints"]
    assert result["assets_analyzed"] == 1


def test_maximum_profile_expands_web_and_subdomain_coverage():
    req = FullScanRequest(target="https://example.com", scan_profile="maximum")
    cfg = resolve_profile("maximum", req.model_dump(mode="json"))
    assert cfg["web_profile"] == "maximum"
    assert cfg["max_pages"] == 500
    assert cfg["max_depth"] == 8
    assert cfg["subdomain_max_hosts"] == 500
