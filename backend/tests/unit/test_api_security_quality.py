from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.modules.api_security.scanner import APISecurityScanner
from app.modules.api_security.templates.engine import APITemplateEngine
from app.schemas.api_security import APIEndpoint, APIMethodObservation
from app.schemas.platform import NormalizedFinding, FindingEvidence
from app.modules.normalizer.normalizer import normalize_bundle
from app.modules.risk_engine.engine import assess, bundle_score


class FakeResponse:
    def __init__(self, status_code=200, payload=None, content_type="application/json"):
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self._payload = payload if payload is not None else {"ok": True}

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_schema_validation_checks_only_observed_status():
    scanner = APISecurityScanner()
    spec = {
        "paths": {
            "/secure": {
                "get": {
                    "responses": {
                        "200": {"content": {"application/json": {"schema": {"type": "object", "required": ["ok"]}}}},
                        "422": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    }
                }
            }
        }
    }
    endpoint = APIEndpoint(
        path="/secure", url="http://127.0.0.1:8000/secure", methods=["GET"],
        observations=[APIMethodObservation(method="GET", status_code=401)],
    )
    client = type("C", (), {"request": AsyncMock(return_value=FakeResponse(401))})()
    result = await scanner._validate_openapi_schemas(client, spec, [endpoint], {})
    assert result == []


def test_method_advertisement_does_not_flag_normal_405_allow():
    engine = APITemplateEngine(Path("backend/app/modules/api_security/templates"))
    matches = engine.evaluate(
        "http://127.0.0.1:8000/api/v1/network/scan", 405, {"allow": "POST"},
        auth_present=False, security_declared=False, declared_methods=["POST"],
    )
    assert not any(m.template_id == "api-methods-advertised" for m in matches)


def test_method_advertisement_flags_undeclared_method():
    engine = APITemplateEngine(Path("backend/app/modules/api_security/templates"))
    matches = engine.evaluate(
        "http://127.0.0.1:8000/api/v1/network/scan", 405, {"allow": "POST, TRACE"},
        auth_present=False, security_declared=False, declared_methods=["POST"],
    )
    assert any(m.template_id == "api-methods-advertised" for m in matches)


def test_missing_credentials_are_not_normalized_as_medium_finding():
    api = type("API", (), {
        "template_matches": [], "schema_validations": [],
        "auth_findings": [], "target": "http://127.0.0.1:8000",
    })()
    findings = normalize_bundle(api=api)
    assert findings == []


def test_info_findings_do_not_raise_risk_score():
    f = NormalizedFinding(
        finding_id="info", source_module="api_security", title="API info", severity="Info",
        confidence=1.0, evidence=[FindingEvidence(source="test", asset="x", evidence="info")],
        affected_asset="x",
    )
    assert assess(f).score == 0.0
    assert bundle_score([f]) == 0.0
