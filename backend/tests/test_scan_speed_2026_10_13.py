"""Regression tests for the 2026-10-13 scan-speed fixes (UDP clamp, circuit breaker, budgets)."""
import asyncio
import time

import httpx
import pytest

from app.core.request_budget import GuardedTransport, RequestBudget, TargetUnreachableError
from app.modules.network_scan.scanner import NetworkScanner


def test_maximum_profile_udp_is_clamped_to_top_ports():
    n = NetworkScanner()
    cmd = n._build_command("host.docker.internal", "maximum", None, None)
    _p1, _p2, udp = n._two_phase_commands(cmd)
    assert udp is not None
    joined = " ".join(udp)
    assert "1-65535" not in joined
    assert "--top-ports 200" in joined
    assert "--max-retries 1" in joined and "--host-timeout" in joined
    # TCP discovery keeps the full range.
    assert "1-65535" in " ".join(_p1)


@pytest.mark.parametrize("ports,expected", [
    (["-p", "1-65535"], ["--top-ports", "200"]),
    (["-p", "53,161"], ["-p", "53,161"]),
    (["--top-ports", "1000"], ["--top-ports", "200"]),
    (["--top-ports", "50"], ["--top-ports", "50"]),
    ([], ["--top-ports", "200"]),
])
def test_clamp_udp_ports(ports, expected):
    assert NetworkScanner._clamp_udp_ports(ports) == expected


def test_guarded_transport_opens_circuit_after_consecutive_connect_failures():
    async def run():
        # Port 9 on loopback is closed in the test sandbox; every attempt is a ConnectError.
        transport = GuardedTransport(RequestBudget(), fail_limit=3)
        async with httpx.AsyncClient(transport=transport, timeout=2.0) as client:
            for _ in range(3):
                with pytest.raises(httpx.HTTPError):
                    await client.get("http://203.0.113.1:9/", timeout=0.2)
            started = time.monotonic()
            with pytest.raises(TargetUnreachableError):
                await client.get("http://203.0.113.1:9/")
            assert time.monotonic() - started < 0.5, "tripped circuit must fail instantly"
            assert transport.tripped
    asyncio.run(run())


def test_profile_tool_caps_are_short_for_quick_and_standard():
    from app.core.config import PROFILE_TOOL_CAPS_SECONDS, Settings
    assert PROFILE_TOOL_CAPS_SECONDS["quick"]["sqlmap"] <= 300
    assert all(v <= 1800 for v in PROFILE_TOOL_CAPS_SECONDS["standard"].values())
    assert Settings().NETWORK_LONG_PROFILE_TIMEOUT_SECONDS <= 3600


def test_engine_preflight_translates_loopback_before_probing(monkeypatch):
    """Regression: the global external preflight probed 127.0.0.1 inside the container and failed."""
    from app.modules.external_scanners import engines
    monkeypatch.setattr(engines, "resolve_loopback_host", lambda port, force=False: "203.0.113.7")
    seen = []

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url):
            seen.append(url)
            return object()

    monkeypatch.setattr(engines.httpx, "AsyncClient", _Client)
    ok, why = asyncio.run(engines._preflight("http://127.0.0.1:3000/#/", attempts=1))
    assert ok and why is None
    assert seen == ["http://203.0.113.7:3000/"], seen


def test_preflight_failure_message_names_probed_address(monkeypatch):
    import asyncio
    import httpx
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines, "resolve_loopback_host", lambda port, force=False: "host.docker.internal")

    class _Boom:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): raise httpx.ConnectError("refused")

    monkeypatch.setattr(engines.httpx, "AsyncClient", _Boom)
    ok, why = asyncio.run(engines._preflight("http://127.0.0.1:3000/#/", attempts=1))
    assert not ok
    assert "http://host.docker.internal:3000/" in why and "0.0.0.0" in why


def test_manager_uses_single_effective_target_and_evidence_override():
    src = open("app/core/architecture/manager.py", encoding="utf-8").read()
    for fn in ("run_zap", "run_ffuf", "run_nuclei", "run_sqlmap_multi", "run_testssl"):
        assert f"{fn}(ext_target" in src and f"{fn}(web_target" not in src
    assert "normalize_engine_target, web_target" in src
    assert "web stage reached the target" in src
