import hashlib
import json

from app.core.rate_limit import _rate_limit_key
from app.modules.ai_analysis.analyzer import AIAnalyzer, _sanitize_for_ai


def test_rate_limit_key_never_contains_raw_api_key():
    class Request:
        headers = {"x-api-key": "super-secret-api-key"}

    key = _rate_limit_key(Request())
    assert "super-secret-api-key" not in key
    assert key == "apikey:" + hashlib.sha256(b"super-secret-api-key").hexdigest()


def test_ai_payload_redacts_auth_headers_tokens_cookies_and_sensitive_query_values():
    raw = {
        "Authorization": "Bearer super-secret-token",
        "Cookie": "session=super-secret-cookie",
        "api_key": "super-secret-api-key",
        "url": "https://example.test/?token=super-secret-token&x=1",
        "evidence": "Authorization: Bearer super-secret-token",
    }
    sanitized = _sanitize_for_ai(raw)
    payload = json.dumps(sanitized, ensure_ascii=False)
    assert "super-secret-token" not in payload
    assert "super-secret-cookie" not in payload
    assert "super-secret-api-key" not in payload
    assert "[REDACTED]" in payload
