"""DefectDojo page scoped to ONE MIRSAD scan (``?scan_id=``).

The importer stores each scan as engagement ``MIRSAD Scan <scan_id>`` inside the
tenant's own product. These tests pin down that the scoped endpoints:
  * filter findings by that engagement (not by the whole instance),
  * report an un-synced scan as ``synced: False`` instead of an error/empty-looking success,
  * resolve the engagement through the CALLER'S tenant product only (no cross-tenant reads),
  * reject malformed scan ids before they reach DefectDojo.
"""
import pytest
from fastapi import HTTPException

from app.api.routes import platform
from app.core.auth_context import tenant_context
from app.core.config import settings
from app.integrations.defectdojo import client as dd_client
from app.integrations.defectdojo import health as dd_health


class FakeDD:
    """Stands in for DefectDojoClient.request; records every call."""
    calls: list = []

    @staticmethod
    def product_name(tenant):
        return f"{settings.DEFECTDOJO_PRODUCT_PREFIX} / {tenant}"

    async def request(self, method, path, **kw):
        params = kw.get("params") or {}
        FakeDD.calls.append((path, dict(params)))
        if path == "/api/v2/products/":
            rows = [{"id": 7, "name": FakeDD.product_name("t1")}, {"id": 8, "name": FakeDD.product_name("t2")}]
            if "name" in params:
                rows = [r for r in rows if r["name"] == params["name"]]
            return {"count": len(rows), "results": rows}
        if path == "/api/v2/engagements/":
            if params.get("product") == 7 and params.get("name") == "MIRSAD Scan S1":
                return {"count": 1, "results": [{"id": 70, "name": "MIRSAD Scan S1", "product": 7}]}
            if "product" in params:
                return {"count": 0, "results": []}
            return {"count": 1, "results": [{"id": 70, "name": "MIRSAD Scan S1", "product": 7}]}
        if path == "/api/v2/tests/":
            return {"count": 1, "results": [{"id": 700, "engagement": 70, "title": "MIRSAD Scan S1"}]}
        if path == "/api/v2/findings/":
            sev = params.get("severity")
            n = {"Critical": 1, "High": 2}.get(sev, 0) if "test__engagement" in params and sev else 3
            return {"count": n if "limit" in params and params["limit"] == 1 else 1,
                    "results": [{"id": 9001, "title": "Reflected XSS", "severity": "High", "test": 700, "active": True}]}
        return {"count": 0, "results": []}


@pytest.fixture(autouse=True)
def _patch(monkeypatch):
    FakeDD.calls = []
    monkeypatch.setattr(dd_client.DefectDojoClient, "request", FakeDD.request)
    async def up(): return "AVAILABLE"
    monkeypatch.setattr(dd_health, "health", up)
    token = tenant_context.set("t1")
    yield
    tenant_context.reset(token)


def finding_params():
    return [p for path, p in FakeDD.calls if path == "/api/v2/findings/"]


async def test_scan_scope_filters_by_that_scans_engagement():
    out = await platform.defectdojo_findings(limit=25, scan_id="S1")
    assert out["scan_scope"] == {"scan_id": "S1", "synced": True, "engagement_id": 70}
    assert out["error"] is None and [f["id"] for f in out["findings"]] == [9001]
    (params,) = finding_params()
    assert params["test__engagement"] == 70
    assert "test__engagement__product" not in params


async def test_scan_scope_ignores_product_filter():
    await platform.defectdojo_findings(limit=25, scan_id="S1", product=8)
    (params,) = finding_params()
    assert params["test__engagement"] == 70 and "test__engagement__product" not in params


async def test_unsynced_scan_is_reported_not_faked_and_findings_are_not_queried():
    out = await platform.defectdojo_findings(limit=25, scan_id="S2")
    assert out["scan_scope"] == {"scan_id": "S2", "synced": False, "engagement_id": None}
    assert out["findings"] == [] and out["total"] == 0 and out["error"] is None
    assert finding_params() == []


async def test_other_tenant_cannot_reach_the_engagement_even_with_the_right_scan_id():
    tenant_context.set("t2")           # t2's product (id 8) has no "MIRSAD Scan S1"
    out = await platform.defectdojo_findings(limit=25, scan_id="S1")
    assert out["scan_scope"]["synced"] is False and out["findings"] == []
    assert finding_params() == []
    eng_calls = [p for path, p in FakeDD.calls if path == "/api/v2/engagements/"]
    assert eng_calls and all(p["product"] == 8 for p in eng_calls)


async def test_without_scan_id_behaviour_is_unchanged():
    out = await platform.defectdojo_findings(limit=25, product=7)
    assert out["scan_scope"] is None
    (params,) = finding_params()
    assert params["test__engagement__product"] == 7 and "test__engagement" not in params


@pytest.mark.parametrize("bad", ["../etc/passwd", "a b", "x" * 200, "S1;drop", "S1/../S2", ""])
async def test_malformed_scan_id_is_rejected_before_any_request(bad):
    if bad == "":
        out = await platform.defectdojo_findings(limit=5, scan_id=bad)   # empty == "no scope"
        assert out["scan_scope"] is None
        return
    with pytest.raises(HTTPException) as e:
        await platform.defectdojo_findings(limit=5, scan_id=bad)
    assert e.value.status_code == 422 and FakeDD.calls == []


async def test_dashboard_counts_are_scoped_to_the_scan():
    out = await platform.defectdojo_dashboard(scan_id="S1")
    assert out["scan_scope"]["synced"] is True
    assert out["products"] == 1 and out["engagements"] == 1
    scoped = [p for path, p in FakeDD.calls if path == "/api/v2/findings/"]
    assert scoped and all(p.get("test__engagement") == 70 for p in scoped)
    assert out["findings_by_severity"]["Critical"] == 1 and out["findings_by_severity"]["High"] == 2


async def test_dashboard_unsynced_scan_has_zero_counts_and_flag():
    out = await platform.defectdojo_dashboard(scan_id="S2")
    assert out["scan_scope"] == {"scan_id": "S2", "synced": False, "engagement_id": None}
    assert out["findings"] == 0 and sum(out["findings_by_severity"].values()) == 0


async def test_dashboard_without_scan_id_is_the_global_view():
    out = await platform.defectdojo_dashboard()
    assert out["scan_scope"] is None
    assert all("test__engagement" not in p for path, p in FakeDD.calls if path == "/api/v2/findings/")
