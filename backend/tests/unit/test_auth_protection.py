from app.modules.web_scan.auth_protection import analyze_auth_protection


def test_auth_protection_discovers_captcha_and_rate_limit():
    result = analyze_auth_protection(
        forms=[{"action": "https://example.test/login", "method": "POST"}],
        rendered_html=[{
            "url": "https://example.test/login",
            "html": '<div class="g-recaptcha"></div>',
        }],
        xhr_requests=[{
            "url": "https://example.test/api/login",
            "method": "POST",
        }],
        responses=[{
            "url": "https://example.test/api/login",
            "method": "POST",
            "status": 429,
            "headers": {"retry-after": "10", "x-ratelimit-remaining": "0"},
        }],
        origin_url="https://example.test/",
    )
    assert len(result["authentication_endpoints"]) == 2
    assert result["captcha_evidence"]
    assert result["rate_limit_observations"]
    assert result["active_credential_attack"] is False


def test_auth_protection_does_not_claim_lockout_without_evidence():
    result = analyze_auth_protection(
        forms=[{"action": "https://example.test/signin", "method": "POST"}],
        origin_url="https://example.test/",
    )
    statuses = {f["check"]: f["status"] for f in result["findings"]}
    assert statuses["account_lockout_backoff"] == "NOT_VERIFIED"
    assert statuses["server_side_captcha_enforcement"] == "NOT_VERIFIED"
