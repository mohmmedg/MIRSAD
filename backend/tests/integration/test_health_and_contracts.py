from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_is_liveness_only():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readiness_contract():
    r = client.get("/readiness")
    assert r.status_code in (200, 503)
    body = r.json()
    assert body["status"] in {"ready", "not_ready"}
    assert "nmap" in body["checks"]


def test_openapi_contains_expected_security_and_scan_routes():
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    assert "/api/v1/network/scan" in paths
    assert "/api/v1/web/scan" in paths
    assert "/api/v1/scans/{scan_id}/status" in paths
    assert "/api/v1/platform/scan/async" in paths


def test_graphql_and_openapi_contracts_are_exposed_in_api_schema():
    schema = client.get("/openapi.json").json()
    schemas = schema["components"]["schemas"]
    assert "GraphQLInfo" in schemas
    assert "OpenAPISummary" in schemas
