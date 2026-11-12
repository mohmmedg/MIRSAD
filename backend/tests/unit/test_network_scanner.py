"""
tests/unit/test_network_scanner.py

اختبارات NetworkScanner مع mocking كامل لـ asyncio.create_subprocess_exec
— بدون أي حاجة لـ nmap مثبّت فعلياً أو اتصال شبكة حقيقي.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.config import ScopeViolationError, SSRFRiskError
from app.modules.network_scan.scanner import NetworkScanner
from app.schemas.network import ScanStatus

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
</port>
<port protocol="tcp" portid="80">
<state state="closed"/>
<service name="http"/>
</port>
</ports>
<os>
<osmatch name="Linux 5.X" accuracy="95"/>
</os>
</host>
</nmaprun>"""


@pytest.fixture
def scanner():
    return NetworkScanner()


class TestScanTypeValidation:
    @pytest.mark.asyncio
    async def test_rejects_unknown_scan_type(self, scanner):
        with pytest.raises(ValueError, match="scan_type"):
            await scanner.scan(target="127.0.0.1", scan_type="ultra")


class TestScopeAndSSRFEnforcement:
    @pytest.mark.asyncio
    async def test_rejects_out_of_scope_target_before_running_nmap(self, scanner):
        with pytest.raises(ScopeViolationError):
            await scanner.scan(target="8.8.8.8", scan_type="quick")

    @pytest.mark.asyncio
    async def test_rejects_ssrf_risk_target_before_running_nmap(self, scanner):
        with pytest.raises(SSRFRiskError):
            await scanner.scan(target="169.254.169.254", scan_type="quick")


class TestCommandBuilding:
    def test_build_command_does_not_shell_quote_target(self, scanner):
        """تأكيد إصلاح shlex.quote(): الهدف يمر خام بالقائمة، بدون علامات
        اقتباس إضافية (لأنه argv مباشر عبر create_subprocess_exec)."""
        command = scanner._build_command("127.0.0.1", "quick", None, None)
        assert "127.0.0.1" in command
        assert "'127.0.0.1'" not in command

    def test_build_command_includes_scan_type_args(self, scanner):
        command = scanner._build_command("127.0.0.1", "comprehensive", None, None)
        assert "-p-" in command
        assert "-oX" in command


class TestParseXML:
    def test_parses_open_ports_and_os_matches(self, scanner):
        parsed = scanner._parse_xml(SAMPLE_NMAP_XML)
        open_ports = parsed["open_ports"]
        os_matches = parsed["os_matches"]
        assert len(open_ports) == 2
        ssh_port = next(p for p in open_ports if p.port == 22)
        assert ssh_port.service_name == "ssh"
        assert ssh_port.product == "OpenSSH"
        assert ssh_port.version == "8.9"
        assert len(os_matches) == 1
        assert os_matches[0].name == "Linux 5.X"
        assert os_matches[0].accuracy == 95

    def test_parses_empty_result_for_down_host(self, scanner):
        xml_no_host = '<?xml version="1.0"?><nmaprun></nmaprun>'
        parsed = scanner._parse_xml(xml_no_host)
        assert parsed["open_ports"] == []
        assert parsed["os_matches"] == []


class TestFullScanFlow:
    @pytest.mark.asyncio
    async def test_successful_scan_returns_completed_result(self, scanner):
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock(
            return_value=(SAMPLE_NMAP_XML.encode(), b"")
        )
        mock_process.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            result = await scanner.scan(target="127.0.0.1", scan_type="quick")

        assert result.status == ScanStatus.COMPLETED
        assert len(result.open_ports) == 2
        assert result.target == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_nmap_binary_not_found_returns_failed_status(self, scanner):
        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=FileNotFoundError()),
        ):
            result = await scanner.scan(target="127.0.0.1", scan_type="quick")

        assert result.status == ScanStatus.FAILED
        assert result.error_message is not None
        assert "nmap" in result.error_message

    @pytest.mark.asyncio
    async def test_nmap_nonzero_exit_returns_failed_status(self, scanner):
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock(return_value=(b"", b"some nmap error"))
        mock_process.returncode = 1

        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            result = await scanner.scan(target="127.0.0.1", scan_type="quick")

        assert result.status == ScanStatus.FAILED
        assert "some nmap error" in result.error_message


def test_top_port_selector_is_translated_to_valid_nmap_syntax(scanner):
    command = scanner._build_command("127.0.0.1", "quick", "top100", None)
    assert "--top-ports" in command
    assert "100" in command
    assert "-p" not in command


def test_parser_aggregates_multiple_nmap_hosts(scanner):
    xml = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
<host><status state="up"/><address addr="192.0.2.11" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>
</nmaprun>"""
    parsed = scanner._parse_xml(xml)
    assert parsed["host_count"] == 2
    assert set(parsed["addresses"]) == {"192.0.2.10", "192.0.2.11"}
    assert {p.port for p in parsed["open_ports"]} == {80, 443}
