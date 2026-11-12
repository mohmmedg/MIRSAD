from app.core.config import settings
from app.core.oob import issue_token, mark, observed
from app.modules.advanced_security import AdvancedSecurityEngine


def test_deep_assessment_ceilings_are_not_legacy_caps():
    assert settings.MAX_ASSESSMENT_PAGES >= 5000
    assert settings.MAX_ASSESSMENT_DEPTH >= 16
    assert settings.MAX_ASSESSMENT_REQUESTS >= 500000
    assert settings.MAX_ASSESSMENT_CONCURRENCY >= 32
    assert settings.MAX_ASSESSMENT_RPS >= 50


def test_oob_callback_correlation_lifecycle():
    token = issue_token(60)
    assert not observed(token)
    assert mark(token) is True
    assert observed(token)


def test_parameter_inventory_collects_forms_and_openapi():
    class Form:
        input_types = {"email": "email", "upload": "file"}
    class Endpoint:
        parameters = ["id"]
    class Param:
        name = "filter"
        location = "query"
    class Web:
        discovered_parameters = {"q": ["query"]}
        forms = [Form()]
        endpoints = [Endpoint()]
    class API:
        openapi_parameters = [Param()]
    result = AdvancedSecurityEngine._collect_parameters(Web(), API())
    assert set(result) >= {"q", "email", "upload", "id", "filter"}
