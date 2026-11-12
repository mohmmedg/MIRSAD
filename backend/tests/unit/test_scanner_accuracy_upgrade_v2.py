"""Regression tests for the TLS/GraphQL/WebSocket accuracy upgrade.

Covers:
  - TLS: per-version handshake probing distinguishes ENABLED / NOT_SUPPORTED /
    NOT_TESTED (never guessing when the local TLS stack itself can't attempt a
    version), and weak-cipher detection from a real negotiated cipher.
  - GraphQL: a verified introspection response produces an Info-disclosure
    finding, but only when a schema was actually retrieved.
  - WebSocket: discovery only ever probes candidates literally observed in
    crawled source (never guessed paths), the handshake probe is HTTP-level
    only, and findings are only ever emitted from a verified accepted
    handshake / origin reflection.
"""
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.modules.api_security.scanner import APISecurityScanner
from app.modules.normalizer.normalizer import normalize_bundle
from app.modules.web_scan.scanner import WebScanner
from app.schemas.api_security import APISecurityResult, GraphQLInfo, WebSocketEndpoint
from app.schemas.network import ScanStatus
from app.schemas.web import HeaderCheck, TLSInfo, WebScanResult


def _base_web_result(**overrides) -> WebScanResult:
    defaults = dict(
        scan_id="fake-web-scan", target="https://example.com",
        status=ScanStatus.COMPLETED, started_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return WebScanResult(**defaults)


def _base_api_result(**overrides) -> APISecurityResult:
    defaults = dict(
        scan_id="fake-api-scan", target="https://example.com",
        status=ScanStatus.COMPLETED.value, started_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return APISecurityResult(**defaults)


class TestTLSProtocolAndCipher:
    def test_local_unsupported_protocol_is_not_tested_not_not_supported(self):
        """If the local OpenSSL build refuses to even attempt a version, that must
        never be reported as the server rejecting it — the two are not the same claim."""
        scanner = WebScanner()

        def fake_wrap(self, sock, server_hostname=None):
            raise __import__("ssl").SSLError("[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol")

        with patch("socket.create_connection", return_value=MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False)), \
             patch("ssl.SSLContext.wrap_socket", new=fake_wrap):
            support = scanner._check_tls_protocol_support("example.com", 443)
        assert support["TLSv1"]["status"] == "NOT_TESTED"
        assert "reason" in support["TLSv1"]

    def test_server_rejection_is_not_supported(self):
        scanner = WebScanner()

        def fake_wrap(self, sock, server_hostname=None):
            raise __import__("ssl").SSLError("[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version")

        with patch("socket.create_connection", return_value=MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False)), \
             patch("ssl.SSLContext.wrap_socket", new=fake_wrap):
            support = scanner._check_tls_protocol_support("example.com", 443)
        assert support["TLSv1"]["status"] == "NOT_SUPPORTED"

    def test_successful_handshake_marks_enabled(self):
        scanner = WebScanner()
        with patch("socket.create_connection", return_value=MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False)), \
             patch("ssl.SSLContext.wrap_socket", return_value=MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False)):
            support = scanner._check_tls_protocol_support("example.com", 443)
        assert support["TLSv1.2"]["status"] == "ENABLED"

    def test_weak_cipher_flagged_from_real_negotiation(self):
        scanner = WebScanner()
        mock_tls_sock = MagicMock()
        mock_tls_sock.getpeercert.return_value = {}
        mock_tls_sock.version.return_value = "TLSv1.2"
        mock_tls_sock.cipher.return_value = ("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128)
        mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
        mock_tls_sock.__exit__ = MagicMock(return_value=False)
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_tls_sock
        mock_sock = MagicMock(__enter__=lambda s: mock_sock, __exit__=lambda *a: False)
        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_context), \
             patch.object(scanner, "_check_tls_protocol_support", return_value={}):
            tls_info = scanner._check_tls("example.com", 443)
        assert tls_info.weak_cipher is True
        assert "RC4" in tls_info.weak_cipher_detail

    def test_normalizer_emits_weak_protocol_and_cipher_findings(self):
        web = _base_web_result(tls_info=TLSInfo(
            enabled=True, protocol_version="TLSv1.2", weak_protocols_enabled=["TLSv1"],
            weak_cipher=True, weak_cipher_detail="RC4-SHA",
        ))
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        rule_ids = {f.rule_id for f in findings}
        assert "WEB-TLS-WEAK-PROTOCOL" in rule_ids
        assert "WEB-TLS-WEAK-CIPHER" in rule_ids
        proto_finding = next(f for f in findings if f.rule_id == "WEB-TLS-WEAK-PROTOCOL")
        assert proto_finding.verification_status == "VERIFIED"

    def test_no_weak_tls_findings_when_only_strong_protocol_seen(self):
        web = _base_web_result(tls_info=TLSInfo(enabled=True, protocol_version="TLSv1.3"))
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert not any(f.rule_id.startswith("WEB-TLS-WEAK") for f in findings)


class TestGraphQLIntrospectionFinding:
    def test_finding_emitted_only_when_schema_actually_retrieved(self):
        api = _base_api_result(graphql=GraphQLInfo(
            discovered=True, introspection_attempted=True, type_count=12,
            field_count=40, endpoint="https://example.com/graphql",
        ))
        findings = normalize_bundle(api=api, scan_id="fake-api-scan")
        rule_ids = {f.rule_id for f in findings}
        assert "API-GRAPHQL-INTROSPECTION-ENABLED" in rule_ids
        finding = next(f for f in findings if f.rule_id == "API-GRAPHQL-INTROSPECTION-ENABLED")
        assert finding.severity == "Low"
        assert finding.verification_status == "VERIFIED"

    def test_no_finding_when_introspection_not_attempted_or_empty(self):
        api = _base_api_result(graphql=GraphQLInfo(discovered=True, introspection_attempted=False))
        findings = normalize_bundle(api=api, scan_id="fake-api-scan")
        assert not any(f.rule_id == "API-GRAPHQL-INTROSPECTION-ENABLED" for f in findings)

        api2 = _base_api_result(graphql=GraphQLInfo(discovered=True, introspection_attempted=True, type_count=0))
        findings2 = normalize_bundle(api=api2, scan_id="fake-api-scan")
        assert not any(f.rule_id == "API-GRAPHQL-INTROSPECTION-ENABLED" for f in findings2)


class TestRequestSafeRegression:
    """Regression test for a real production bug found via manual Docker testing:
    _request_safe called resolve_safe_target() without importing it, so every
    request that goes through redirect-following (i.e. almost every API scan
    request) raised NameError and the whole module failed with
    'API scan failed: name resolve_safe_target is not defined'."""

    @pytest.mark.asyncio
    async def test_request_safe_does_not_raise_undefined_name_error(self):
        scanner = APISecurityScanner()
        response = httpx.Response(200, request=httpx.Request("GET", "https://example.com/api"))
        client = MagicMock()
        client.request = AsyncMock(return_value=response)
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            result = await scanner._request_safe(client, "GET", "https://example.com/api")
        assert result.status_code == 200


class TestWebSocketDiscoveryAndVerification:
    def test_candidate_extraction_only_uses_literal_urls_in_source(self):
        bodies = [
            "<script>const s = new WebSocket('wss://example.com/socket');</script>",
            "no websocket here",
            "var x = \"ws://insecure.example.com/live\";",
        ]
        candidates = WebScanner._find_websocket_candidates(bodies)
        assert any(c.startswith("wss://example.com/socket") for c in candidates)
        assert any(c.startswith("ws://insecure.example.com/live") for c in candidates)
        # Never invents a candidate that wasn't literally present in source.
        assert not any("guessed" in c for c in candidates)

    @pytest.mark.asyncio
    async def test_accepted_handshake_and_reflected_origin_are_verified(self):
        scanner = APISecurityScanner()
        accepted = httpx.Response(101, headers={"connection": "Upgrade"}, request=httpx.Request("GET", "https://example.com/socket"))
        client = MagicMock()
        client.get = AsyncMock(return_value=accepted)
        with patch("app.modules.api_security.scanner.verify_target_in_scope", return_value=None):
            results = await scanner._discover_websockets(client, ["wss://example.com/socket"], {})
        assert len(results) == 1
        ws = results[0]
        assert ws.handshake_attempted is True
        assert ws.handshake_accepted is True
        assert ws.origin_test_attempted is True
        assert ws.origin_reflected is True  # server accepted the foreign-Origin probe too

    @pytest.mark.asyncio
    async def test_rejected_handshake_is_not_flagged(self):
        scanner = APISecurityScanner()
        rejected = httpx.Response(400, request=httpx.Request("GET", "https://example.com/socket"))
        client = MagicMock()
        client.get = AsyncMock(return_value=rejected)
        with patch("app.modules.api_security.scanner.verify_target_in_scope", return_value=None):
            results = await scanner._discover_websockets(client, ["wss://example.com/socket"], {})
        assert results[0].handshake_accepted is False
        assert results[0].origin_test_attempted is False  # never probed since handshake was refused

    @pytest.mark.asyncio
    async def test_out_of_scope_candidate_is_skipped(self):
        from app.core.config import ScopeViolationError
        scanner = APISecurityScanner()
        client = MagicMock()
        client.get = AsyncMock()
        with patch("app.modules.api_security.scanner.verify_target_in_scope", side_effect=ScopeViolationError("out of scope")):
            results = await scanner._discover_websockets(client, ["wss://not-in-scope.example.org/socket"], {})
        assert results == []
        client.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_handshake_failure_is_recorded_not_raised(self):
        scanner = APISecurityScanner()
        client = MagicMock()
        client.get = AsyncMock(side_effect=RuntimeError("unexpected 101 handling"))
        with patch("app.modules.api_security.scanner.verify_target_in_scope", return_value=None):
            results = await scanner._discover_websockets(client, ["wss://example.com/socket"], {})
        assert results[0].error is not None
        assert results[0].handshake_accepted is False

    def test_normalizer_emits_discovery_and_origin_findings(self):
        api = _base_api_result(websockets=[
            WebSocketEndpoint(
                url="wss://example.com/socket", handshake_attempted=True, handshake_status=101,
                handshake_accepted=True, origin_test_attempted=True, origin_test_status=101,
                origin_reflected=True,
            )
        ])
        findings = normalize_bundle(api=api, scan_id="fake-api-scan")
        rule_ids = {f.rule_id for f in findings}
        assert "API-WEBSOCKET-DISCOVERED" in rule_ids
        assert "API-WEBSOCKET-ORIGIN-UNVALIDATED" in rule_ids
        origin_finding = next(f for f in findings if f.rule_id == "API-WEBSOCKET-ORIGIN-UNVALIDATED")
        assert origin_finding.severity == "Medium"

    def test_normalizer_skips_findings_for_unattempted_or_rejected_candidates(self):
        api = _base_api_result(websockets=[
            WebSocketEndpoint(url="wss://a.example.com/socket", handshake_attempted=False),
            WebSocketEndpoint(url="wss://b.example.com/socket", handshake_attempted=True, handshake_accepted=False, handshake_status=400),
        ])
        findings = normalize_bundle(api=api, scan_id="fake-api-scan")
        assert not any(f.rule_id.startswith("API-WEBSOCKET") for f in findings)


class TestAdvancedHeaderValueAnalysis:
    def test_permissions_policy_flags_sensitive_wildcard(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"permissions-policy": "camera=*, geolocation=(self)"})
        pp = next(c for c in checks if c.header_name == "Permissions-Policy")
        assert "WILDCARD_CAMERA" in pp.analysis
        assert "WILDCARD_GEOLOCATION" not in pp.analysis

    def test_permissions_policy_valid_when_restrictive(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"permissions-policy": "camera=(self), geolocation=()"})
        pp = next(c for c in checks if c.header_name == "Permissions-Policy")
        assert pp.analysis == "VALID"

    def test_x_content_type_options_rejects_non_nosniff_value(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"x-content-type-options": "sniff-allowed"})
        c = next(c for c in checks if c.header_name == "X-Content-Type-Options")
        assert c.analysis == "INVALID"

    def test_x_frame_options_allow_from_is_weak(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"x-frame-options": "ALLOW-FROM https://example.com"})
        c = next(c for c in checks if c.header_name == "X-Frame-Options")
        assert c.analysis == "WEAK"

    def test_x_frame_options_deny_is_valid(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"x-frame-options": "DENY"})
        c = next(c for c in checks if c.header_name == "X-Frame-Options")
        assert c.analysis == "VALID"

    def test_referrer_policy_unsafe_url_is_weak(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"referrer-policy": "unsafe-url"})
        c = next(c for c in checks if c.header_name == "Referrer-Policy")
        assert c.analysis == "WEAK"

    def test_coop_unsafe_none_is_weak(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"cross-origin-opener-policy": "unsafe-none"})
        c = next(c for c in checks if c.header_name == "Cross-Origin-Opener-Policy")
        assert c.analysis == "WEAK"

    def test_corp_cross_origin_is_weak(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"cross-origin-resource-policy": "cross-origin"})
        c = next(c for c in checks if c.header_name == "Cross-Origin-Resource-Policy")
        assert c.analysis == "WEAK"

    def test_coep_require_corp_is_valid(self):
        scanner = WebScanner()
        checks = scanner._check_security_headers({"cross-origin-embedder-policy": "require-corp"})
        c = next(c for c in checks if c.header_name == "Cross-Origin-Embedder-Policy")
        assert c.analysis == "VALID"

    def test_normalizer_emits_config_finding_for_weak_header_value(self):
        web = _base_web_result(security_headers=[
            HeaderCheck(header_name="X-Frame-Options", present=True, value="ALLOW-FROM https://x.test", analysis="WEAK")
        ])
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert any(f.rule_id == "WEB-HEADER-CONFIG-X_FRAME_OPTIONS" for f in findings)

    def test_no_finding_when_header_value_is_valid(self):
        web = _base_web_result(security_headers=[
            HeaderCheck(header_name="X-Frame-Options", present=True, value="DENY", analysis="VALID")
        ])
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert not any(f.rule_id.startswith("WEB-HEADER-CONFIG") for f in findings)


class TestCookieAnalysisUpgrade:
    def test_samesite_none_without_secure_is_flagged(self):
        scanner = WebScanner()
        notes = scanner._check_cookies(["session=x; SameSite=None"])
        assert any("SameSite=None" in n for n in notes)

    def test_samesite_none_with_secure_is_not_flagged_for_that_rule(self):
        scanner = WebScanner()
        notes = scanner._check_cookies(["session=x; SameSite=None; Secure; HttpOnly"])
        assert not any("SameSite=None" in n for n in notes)

    def test_normalizer_emits_verified_cookie_findings_scaled_by_sensitivity(self):
        web = _base_web_result(cookie_details=[
            {"name": "session", "kind": "sensitive", "secure": False, "httponly": False, "samesite": None},
            {"name": "theme", "kind": "non-sensitive", "secure": False, "httponly": False, "samesite": None},
        ])
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        sensitive = [f for f in findings if f.affected_asset == web.target and "session" in (f.evidence[0].evidence if f.evidence else "")]
        non_sensitive = [f for f in findings if f.evidence and "theme" in f.evidence[0].evidence]
        assert any(f.rule_id == "WEB-COOKIE-MISSING-SECURE" and f.severity == "Medium" for f in sensitive)
        assert any(f.rule_id == "WEB-COOKIE-MISSING-HTTPONLY" for f in sensitive)
        assert any(f.rule_id == "WEB-COOKIE-MISSING-SECURE" and f.severity == "Low" for f in non_sensitive)
        # Non-sensitive cookies are never held to the HttpOnly/SameSite bar.
        assert not any(f.rule_id == "WEB-COOKIE-MISSING-HTTPONLY" for f in non_sensitive)

    def test_no_cookie_findings_when_fully_configured(self):
        web = _base_web_result(cookie_details=[
            {"name": "session", "kind": "sensitive", "secure": True, "httponly": True, "samesite": "Strict"},
        ])
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert not any(f.rule_id.startswith("WEB-COOKIE") for f in findings)


class TestCacheControlSensitiveCookieCorrelation:
    """Cache-Control is only ever flagged when correlated with a concrete sensitive
    cookie on the same response — never from a bare 'header missing' signal alone."""

    def test_flagged_when_sensitive_cookie_present_and_no_store_missing(self):
        web = _base_web_result(
            cookie_details=[{"name": "session", "kind": "sensitive", "secure": True, "httponly": True, "samesite": "Strict"}],
            security_headers=[HeaderCheck(header_name="Cache-Control", present=True, value="public, max-age=3600", analysis="PRESENT")],
        )
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert any(f.rule_id == "WEB-CACHE-SENSITIVE-CACHEABLE" for f in findings)

    def test_flagged_when_cache_control_absent_entirely(self):
        web = _base_web_result(cookie_details=[{"name": "session", "kind": "sensitive", "secure": True, "httponly": True, "samesite": "Strict"}])
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert any(f.rule_id == "WEB-CACHE-SENSITIVE-CACHEABLE" for f in findings)

    def test_not_flagged_when_no_store_present(self):
        web = _base_web_result(
            cookie_details=[{"name": "session", "kind": "sensitive", "secure": True, "httponly": True, "samesite": "Strict"}],
            security_headers=[HeaderCheck(header_name="Cache-Control", present=True, value="no-store, no-cache", analysis="PRESENT")],
        )
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert not any(f.rule_id == "WEB-CACHE-SENSITIVE-CACHEABLE" for f in findings)

    def test_not_flagged_when_no_sensitive_cookie_present(self):
        """A missing Cache-Control on its own is never treated as a confirmed issue —
        only the correlation with real sensitive-cookie evidence makes it one."""
        web = _base_web_result(cookie_details=[{"name": "theme", "kind": "non-sensitive", "secure": False, "httponly": False, "samesite": None}])
        findings = normalize_bundle(web=web, scan_id="fake-web-scan")
        assert not any(f.rule_id == "WEB-CACHE-SENSITIVE-CACHEABLE" for f in findings)


class TestOpenRedirectCanary:
    @pytest.mark.asyncio
    async def test_offsite_redirect_via_hinted_param_is_flagged(self):
        scanner = WebScanner()
        redirect_response = httpx.Response(
            302, headers={"location": "https://mirsad-redirect-probe.invalid/"},
            request=httpx.Request("GET", "https://example.com/login?next=/home"),
        )
        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=redirect_response)):
            client = httpx.AsyncClient()
            check = await scanner._test_open_redirect(client, "https://example.com/login?next=/home", "next")
        assert check.vulnerable is True
        assert "mirsad-redirect-probe.invalid" in check.evidence

    @pytest.mark.asyncio
    async def test_same_site_redirect_is_not_flagged(self):
        scanner = WebScanner()
        redirect_response = httpx.Response(
            302, headers={"location": "/dashboard"},
            request=httpx.Request("GET", "https://example.com/login?next=/dashboard"),
        )
        with patch.object(httpx.AsyncClient, "get", new=AsyncMock(return_value=redirect_response)):
            client = httpx.AsyncClient()
            check = await scanner._test_open_redirect(client, "https://example.com/login?next=/dashboard", "next")
        assert check.vulnerable is False

    def test_only_hinted_parameter_names_are_tested(self):
        from app.modules.web_scan.scanner import REDIRECT_PARAM_HINTS
        assert any("next" in h for h in REDIRECT_PARAM_HINTS)
        assert not any(h == "q" for h in REDIRECT_PARAM_HINTS)  # a generic search param is never treated as a redirect target

