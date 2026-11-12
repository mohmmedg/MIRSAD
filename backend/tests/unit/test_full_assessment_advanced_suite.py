from __future__ import annotations

from app.core.request_budget import RequestBudget
from app.core.safety_policy import policy_for
from app.modules.advanced_security import AdvancedSecurityEngine
from app.modules.network_scan.scanner import NetworkScanner


def test_safety_modes_are_distinct():
    assert not policy_for("safe").allow_write_methods
    assert policy_for("caution").allow_write_methods
    assert policy_for("caution").allow_delete is False
    assert policy_for("destructive").allow_delete is True
    assert policy_for("destructive").allow_intrusive_template_tags is True


def test_maximum_nmap_scans_full_tcp_and_udp_ranges():
    cmd = NetworkScanner()._build_command("example.com", "maximum", None, None)
    joined = " ".join(cmd)
    assert "T:1-65535,U:1-65535" in joined


def test_shared_budget_has_external_operation_accounting():
    budget = RequestBudget(100, 10, 2)
    assert budget.snapshot()["by_kind"]["http"] == 0
    assert budget.remaining == 100


def test_advanced_engine_is_available():
    assert AdvancedSecurityEngine().__class__.__name__ == "AdvancedSecurityEngine"
