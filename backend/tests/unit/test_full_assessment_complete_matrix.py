from __future__ import annotations

import inspect

from app.modules.advanced_security import AdvancedSecurityEngine
from app.core.request_budget import RequestBudget
from app.core.safety_policy import policy_for


def test_all_18_advanced_families_are_exposed():
    source = inspect.getsource(AdvancedSecurityEngine.scan)
    for name in (
        "websocket_messages", "graphql_advanced", "parser_injections",
        "request_smuggling", "cache_security", "file_upload",
        "race_conditions", "business_logic", "auth_workflows",
        "dom_xss", "command_injection",
    ):
        assert name in source


def test_destructive_policy_and_budget_contract():
    assert policy_for("safe").allow_delete is False
    assert policy_for("caution").allow_delete is False
    assert policy_for("destructive").allow_delete is True
    budget = RequestBudget(max_requests=12, requests_per_second=6, max_concurrency=3)
    snap = budget.snapshot()
    assert snap["max_requests"] == 12
    assert snap["requests_per_second"] == 6
    assert snap["max_concurrency"] == 3
