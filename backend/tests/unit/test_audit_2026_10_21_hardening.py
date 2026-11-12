"""Regression tests for the 2026-10-21 security audit fixes."""
import pytest

from app.modules.importers.nmap_xml import parse_nmap_xml
from app.modules.reporting.exporters import _csv_cell
from app.modules.web_scan.template_marketplace import TemplateValidationError, validate_template


def test_xml_entity_expansion_is_rejected():
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    with pytest.raises(ValueError):
        parse_nmap_xml(bomb, "scan-1")


def test_xml_external_entity_is_rejected():
    xxe = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>'
    with pytest.raises(ValueError):
        parse_nmap_xml(xxe, "scan-1")


@pytest.mark.parametrize("value", ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd"])
def test_csv_formula_cells_are_neutralized(value):
    assert _csv_cell(value).startswith("'")


def test_csv_normal_cells_unchanged():
    assert _csv_cell("SQL injection") == "SQL injection"
    assert _csv_cell(5) == 5


@pytest.mark.parametrize("pattern", ["(a|aa)+b", "(x|x)*y", "(a+)+$"])
def test_redos_prone_template_regex_is_rejected(pattern):
    with pytest.raises(TemplateValidationError):
        validate_template({"id": "redos-test", "name": "t", "path": "/", "body_regex": [pattern]})


def test_safe_template_regex_still_accepted():
    out = validate_template({"id": "safe-test", "name": "t", "path": "/", "body_regex": ["root:x:0:0", "DB_PASSWORD=\\w+"]})
    assert out["body_regex"]


def test_private_targets_blocked_only_when_opted_in(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "BLOCK_PRIVATE_TARGETS", False)
    assert not config._ip_in_blocked_ssrf_ranges("10.0.0.5")
    monkeypatch.setattr(config.settings, "BLOCK_PRIVATE_TARGETS", True)
    for ip in ("10.0.0.5", "127.0.0.1", "192.168.1.1", "172.16.0.9"):
        assert config._ip_in_blocked_ssrf_ranges(ip)
    assert not config._ip_in_blocked_ssrf_ranges("93.184.216.34")
