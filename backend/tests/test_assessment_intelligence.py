from types import SimpleNamespace
from app.modules.assessment_intelligence import classify_parameter, build_endpoint_inventory, evidence_quality


def test_parameter_classification():
    assert "ssrf" in classify_parameter("webhook")
    assert "identifier" in classify_parameter("user_id")
    assert "redirect" in classify_parameter("return_url")


def test_endpoint_inventory_merges_web_and_api():
    web = SimpleNamespace(endpoints=[SimpleNamespace(url="https://x.test/api/users?id=1", method="GET", source="crawler", status_code=200, content_type="application/json", parameters=[])])
    api = SimpleNamespace(endpoints=[SimpleNamespace(url="https://x.test/api/users?id=1", method="GET", parameters=[])])
    rows = build_endpoint_inventory(web, api)
    assert len(rows) == 1
    assert rows[0]["parameters"][0]["name"] == "id"


def test_evidence_quality_is_bounded():
    e = SimpleNamespace(source="a", evidence="x" * 800)
    result = evidence_quality([e])
    assert result["level"] == "HIGH"
    assert 0 <= result["reproducibility"] <= 1
