"""
tests/unit/test_web_scanner.py

اختبارات WebScanner مع mocking لـ httpx.AsyncClient — بدون أي طلبات شبكة
حقيقية.
"""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.core.config import ScopeViolationError, SSRFRiskError
from app.modules.web_scan.scanner import WebScanner
from app.schemas.network import ScanStatus


@pytest.fixture
def scanner():
    return WebScanner()


class TestScopeEnforcement:
    @pytest.mark.asyncio
    async def test_rejects_out_of_scope_hostname(self, scanner):
        with pytest.raises(ScopeViolationError):
            await scanner.scan(target_url="https://google.com/")

    @pytest.mark.asyncio
    async def test_rejects_invalid_url(self, scanner):
        with pytest.raises(ValueError):
            await scanner.scan(target_url="not-a-url")


class TestRedirectScopeEnforcement:
    """يتحقق أن كل قفزة redirect تُفحص ضد Scope Guard/SSRF Protection —
    وليس فقط الرابط الأصلي (راجع _get_with_scope_checked_redirects)."""

    @pytest.mark.asyncio
    async def test_redirect_to_out_of_scope_host_fails_scan(self, scanner):
        redirect_response = httpx.Response(
            302,
            headers={"Location": "https://evil-out-of-scope.example.com/"},
            request=httpx.Request("GET", "https://example.com/"),
        )
        with patch.object(
            httpx.AsyncClient, "request", new=AsyncMock(return_value=redirect_response)
        ):
            result = await scanner.scan(target_url="https://example.com/", profile="quick")

        assert result.status == ScanStatus.FAILED
        assert "غير مصرّح" in result.error_message

    @pytest.mark.asyncio
    async def test_redirect_to_ssrf_blocked_ip_fails_scan(self, scanner):
        redirect_response = httpx.Response(
            302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            request=httpx.Request("GET", "https://example.com/"),
        )
        with patch.object(
            httpx.AsyncClient, "request", new=AsyncMock(return_value=redirect_response)
        ):
            result = await scanner.scan(target_url="https://example.com/", profile="quick")

        assert result.status == ScanStatus.FAILED

    @pytest.mark.asyncio
    async def test_redirect_within_scope_is_followed_successfully(self, scanner):
        redirect_response = httpx.Response(
            302,
            headers={"Location": "https://127.0.0.1/final"},
            request=httpx.Request("GET", "https://example.com/"),
        )
        final_response = httpx.Response(
            200,
            headers={"Server": "nginx"},
            request=httpx.Request("GET", "https://127.0.0.1/final"),
        )
        with patch.object(
            httpx.AsyncClient,
            "request",
            new=AsyncMock(side_effect=[redirect_response, final_response]),
        ), patch.object(scanner, "_check_tls", return_value=None), patch.object(
            scanner, "_run_templates", new=AsyncMock(return_value=([], 0))
        ), patch(
            "app.modules.web_scan.scanner.resolve_safe_target", return_value=["127.0.0.1"]
        ), patch(
            "app.modules.web_scan.scanner.check_ssrf_risk", return_value=None
        ), patch.object(
            type(scanner), "_docker_host_url", staticmethod(lambda u: u)  # no Docker host rewrite in unit tests
        ):
            result = await scanner.scan(target_url="https://example.com/", profile="quick")

        assert result.status == ScanStatus.COMPLETED
        assert result.server_header == "nginx"

    @pytest.mark.asyncio
    async def test_vuln_check_reports_blocked_redirect_instead_of_crashing(self, scanner):
        redirect_response = httpx.Response(
            302,
            headers={"Location": "http://169.254.169.254/"},
            request=httpx.Request("GET", "https://example.com/search"),
        )
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=redirect_response)
        check = await scanner._test_reflected_xss(
            mock_client, "https://example.com/search?q=1", "q"
        )
        assert check.vulnerable is False
        assert "SSRF" in check.evidence


class TestSecurityHeaderCheck:
    def test_detects_present_and_missing_headers(self, scanner):
        headers = {"strict-transport-security": "max-age=31536000"}
        checks = scanner._check_security_headers(headers)
        hsts = next(c for c in checks if c.header_name == "Strict-Transport-Security")
        csp = next(c for c in checks if c.header_name == "Content-Security-Policy")
        assert hsts.present is True
        assert csp.present is False


class TestFullScanFlow:
    @pytest.mark.asyncio
    async def test_successful_scan_returns_completed(self, scanner):
        mock_response = httpx.Response(
            200,
            headers={"Strict-Transport-Security": "max-age=1", "Server": "nginx"},
            request=httpx.Request("GET", "https://example.com/"),
        )
        with patch.object(
            httpx.AsyncClient, "request", new=AsyncMock(return_value=mock_response)
        ), patch.object(scanner, "_check_tls", return_value=None), patch.object(
            scanner, "_run_templates", new=AsyncMock(return_value=([], 0))
        ):
            result = await scanner.scan(target_url="https://example.com/", profile="quick")

        assert result.status == ScanStatus.COMPLETED
        assert result.server_header == "nginx"

    @pytest.mark.asyncio
    async def test_connection_failure_returns_failed_status(self, scanner):
        with patch.object(
            httpx.AsyncClient,
            "request",
            new=AsyncMock(side_effect=httpx.ConnectError("refused")),
        ), patch("app.core.config.check_ssrf_risk", return_value=None):
            result = await scanner.scan(target_url="https://example.com/", profile="quick")

        assert result.status == ScanStatus.FAILED
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_vuln_checks_skipped_without_query_params(self, scanner):
        checks = await scanner._run_templates(None, "https://example.com/page", [], ("https", "example.com", 443))
        assert checks == ([], 0)


class TestVulnerabilityChecks:
    @pytest.mark.asyncio
    async def test_xss_check_detects_unescaped_reflection(self, scanner):
        mock_response = httpx.Response(
            200,
            text='<html><script>sec_scan_xss_marker_9f3a</script></html>',
            request=httpx.Request("GET", "https://example.com/search"),
        )
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        check = await scanner._test_reflected_xss(
            mock_client, "https://example.com/search?q=1", "q"
        )
        assert check.vulnerable is True
        assert check.check_name == "reflected_xss_canary"

    @pytest.mark.asyncio
    async def test_xss_check_not_vulnerable_when_escaped(self, scanner):
        mock_response = httpx.Response(
            200,
            text="&lt;script&gt;safe&lt;/script&gt;",
            request=httpx.Request("GET", "https://example.com/search"),
        )
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        check = await scanner._test_reflected_xss(
            mock_client, "https://example.com/search?q=1", "q"
        )
        assert check.vulnerable is False

    @pytest.mark.asyncio
    async def test_sqli_check_detects_error_signature(self, scanner):
        mock_response = httpx.Response(
            200,
            text="Warning: mysql_fetch_array() expects parameter 1",
            request=httpx.Request("GET", "https://example.com/item"),
        )
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        check = await scanner._test_sqli_error_based(
            mock_client, "https://example.com/item?id=1", "id"
        )
        assert check.vulnerable is True
        assert check.check_name == "sqli_error_based"


class TestTLSCheck:
    def test_tls_check_handles_connection_refused(self, scanner):
        from unittest.mock import patch as mock_patch

        with mock_patch(
            "socket.create_connection", side_effect=ConnectionRefusedError()
        ):
            tls_info = scanner._check_tls("example.com", 443)
        assert tls_info.enabled is True
        assert tls_info.error is not None

    def test_tls_check_parses_valid_certificate(self, scanner):
        from datetime import datetime, timedelta, timezone
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        future_date = (datetime.now(timezone.utc) + timedelta(days=90)).strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
        fake_cert = {
            "notAfter": future_date,
            "issuer": ((("organizationName", "Test CA"),),),
        }
        mock_tls_sock = MagicMock()
        mock_tls_sock.getpeercert.return_value = fake_cert
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
        mock_tls_sock.__exit__ = MagicMock(return_value=False)

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_tls_sock

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with mock_patch("socket.create_connection", return_value=mock_sock), mock_patch(
            "ssl.create_default_context", return_value=mock_context
        ):
            tls_info = scanner._check_tls("example.com", 443)

        assert tls_info.enabled is True
        assert tls_info.certificate_valid is True
        assert tls_info.protocol_version == "TLSv1.3"
        assert tls_info.issuer == "Test CA"