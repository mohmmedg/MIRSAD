from pathlib import Path
import sys
import time

from app.modules.external_scanners.engines import _redact_sqlmap_text


def test_sqlmap_diagnostics_redact_all_query_values_but_keep_parameter_names():
    value = "failed at http://lab.local/search?q=secret-value&token=abc123&sort=recent"
    redacted = _redact_sqlmap_text(value)
    assert "q=%5BREDACTED%5D" in redacted
    assert "token=%5BREDACTED%5D" in redacted
    assert "sort=%5BREDACTED%5D" in redacted
    assert "secret-value" not in redacted
    assert "abc123" not in redacted


def test_sqlmap_diagnostics_redact_url_credentials_and_bearer_tokens():
    value = "https://user:pass@example.test/path?email=person@example.test Authorization: Bearer abc.def.ghi"
    redacted = _redact_sqlmap_text(value)
    assert "user:pass" not in redacted
    assert "person@example.test" not in redacted
    assert "abc.def.ghi" not in redacted


def test_root_compose_zap_allowlist_accepts_service_host_and_private_networks():
    root = Path(__file__).resolve().parents[2]
    for filename in ("docker-compose.yml", "docker-compose.production.yml"):
        content = (root / filename).read_text(encoding="utf-8")
        assert "zap(:8080)?|127\\." in content
        assert "api.addrs.addr.regex=true" in content
        assert "api.disablekey=true" not in content
        import re
        pattern = re.search(r"api\.addrs\.addr\.name=([^']+)", content).group(1)
        assert re.fullmatch(pattern, "zap")
        assert re.fullmatch(pattern, "zap:8080")
        assert re.fullmatch(pattern, "172.18.0.15")
        assert not re.fullmatch(pattern, "public.example.com")
    startup = (root / "zap/start-zap.sh").read_text(encoding="utf-8")
    assert 'api.key=${ZAP_KEY}' in startup
    assert "addAlias" not in startup


def test_ffuf_minimum_duration_estimate_is_a_lower_bound():
    from app.modules.external_scanners.engines import _estimate_ffuf_minimum_seconds

    assert _estimate_ffuf_minimum_seconds(156_991, 80) == 1963
    assert _estimate_ffuf_minimum_seconds(211, 5) == 43
    assert _estimate_ffuf_minimum_seconds(None, 80) is None
    assert _estimate_ffuf_minimum_seconds(100, 0) is None


async def test_external_process_timeout_also_covers_process_after_pipes_close(monkeypatch):
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines, "_available", lambda _binary: True)
    started = time.monotonic()
    result = await engines._run_process_streaming(
        sys.executable,
        ["-c", "import os,time; os.close(1); os.close(2); time.sleep(5)"],
        1,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 3
    assert result[3] == "FAILED"
    assert result[5] == "TIMEOUT"


async def test_semgrep_nonzero_exit_has_reason_and_exit_code(monkeypatch):
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines.settings, "ENABLE_SEMGREP", True)
    monkeypatch.setattr(engines.settings, "SEMGREP_BINARY_PATH", "semgrep")
    monkeypatch.setattr(engines, "_available", lambda _binary: True)

    async def fake_exec(*args, **kwargs):
        return "PARTIAL", 2, "", "invalid local rules configuration"

    async def fake_version(*args, **kwargs):
        return "test-version"

    monkeypatch.setattr(engines, "_run_bounded_exec", fake_exec)
    monkeypatch.setattr(engines, "_binary_version", fake_version)
    result = await engines.run_semgrep_source_scan([("app.js", "const x = 1;")])

    assert result["status"] == "PARTIAL"
    assert result["exit_code"] == 2
    assert "invalid local rules configuration" in result["reason"]


async def test_sqlmap_multi_reports_per_target_failure_without_query_values(monkeypatch):
    from app.modules.external_scanners import engines

    targets = [
        {"url": "http://lab.local/search?q=private-value", "data": None, "extra_args": [], "label": "GET parameters"},
        {"url": "http://lab.local/items?id=2", "data": None, "extra_args": [], "label": "GET parameters"},
    ]
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *args, **kwargs: targets)
    calls = 0

    async def fake_run_sqlmap(url, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"status": "FAILED", "findings": [], "reason": f"could not connect to {url}"}
        return {"status": "COMPLETED", "findings": [], "stdout": "completed", "stderr": ""}

    monkeypatch.setattr(engines, "run_sqlmap", fake_run_sqlmap)
    result = await engines.run_sqlmap_multi(
        "http://lab.local", safe_mode="safe", timeout_seconds=600, max_targets=2
    )

    assert result["status"] == "PARTIAL"
    assert result["targets_tested"][0]["reason"]
    assert "private-value" not in result["reason"]
    assert "private-value" not in result["targets_tested"][0]["url"]
    assert "q=%5BREDACTED%5D" in result["targets_tested"][0]["url"]


def test_semgrep_rules_use_supported_javascript_language_tags():
    import yaml
    from app.modules.external_scanners import engines

    rules_path = Path(engines.__file__).resolve().parent / "rules" / "mirsad-javascript.yml"
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    assert data["rules"]
    assert all(set(rule["languages"]) == {"javascript", "typescript"} for rule in data["rules"])


async def test_semgrep_rule_validation_error_is_failed_not_partial(monkeypatch):
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines.settings, "ENABLE_SEMGREP", True)
    monkeypatch.setattr(engines.settings, "SEMGREP_BINARY_PATH", "semgrep")
    monkeypatch.setattr(engines, "_available", lambda _binary: True)

    async def fake_exec(*args, **kwargs):
        return "PARTIAL", 8, "", "semgrep-core rule validation failed (RuleParseError)"

    async def fake_version(*args, **kwargs):
        return "test-version"

    monkeypatch.setattr(engines, "_run_bounded_exec", fake_exec)
    monkeypatch.setattr(engines, "_binary_version", fake_version)
    result = await engines.run_semgrep_source_scan([("app.js", "const x = 1;")])

    assert result["status"] == "FAILED"
    assert result["exit_code"] == 8
    assert "RuleParseError" in result["reason"]


def test_sqlmap_target_selection_ignores_socket_io_protocol_parameters():
    from types import SimpleNamespace
    from app.modules.external_scanners.engines import select_sqlmap_targets

    web = SimpleNamespace(endpoints=[
        {"url": "http://target.test/socket.io/?EIO=4&transport=polling&t=abc123", "method": "GET", "parameters": ["EIO", "transport", "t"]},
        {"url": "http://target.test/search?id=7", "method": "GET", "parameters": ["id"]},
    ], forms=[])
    targets = select_sqlmap_targets("http://target.test/", endpoints=web.endpoints, forms=web.forms, api_endpoints=[])

    assert len(targets) == 1
    assert targets[0]["url"] == "http://target.test/search?id=7"
    assert targets[0]["label"] == "GET parameters"


def test_sqlmap_target_selection_does_not_fallback_to_unparameterized_root():
    from app.modules.external_scanners.engines import select_sqlmap_targets

    targets = select_sqlmap_targets("http://target.test/", endpoints=[], forms=[], api_endpoints=[])

    assert targets == []


async def test_sqlmap_reports_not_tested_when_only_protocol_endpoints_exist(monkeypatch):
    from types import SimpleNamespace
    from app.modules.external_scanners import engines

    web = SimpleNamespace(endpoints=[
        {"url": "http://target.test/socket.io/?EIO=4&transport=polling&t=abc123", "method": "GET", "parameters": ["EIO", "transport", "t"]}
    ], forms=[])
    api = SimpleNamespace(endpoints=[])

    async def unexpected_run(*args, **kwargs):
        raise AssertionError("SQLMap must not run against protocol-only endpoints")

    monkeypatch.setattr(engines, "run_sqlmap", unexpected_run)
    result = await engines.run_sqlmap_multi(
        "http://target.test/", web=web, api=api, safe_mode="safe", timeout_seconds=120
    )

    assert result["status"] == "NOT_TESTED"
    assert "injectable parameters" in result["reason"]


def test_sqlmap_keeps_legitimate_timestamp_parameter_outside_engine_io():
    from app.modules.external_scanners.engines import select_sqlmap_targets

    targets = select_sqlmap_targets(
        "http://target.test/",
        endpoints=[{"url": "http://target.test/search?t=2026", "method": "GET", "parameters": ["t"]}],
        forms=[], api_endpoints=[],
    )

    assert len(targets) == 1
    assert "t=2026" in targets[0]["url"]


async def test_sqlmap_unreachable_reason_shows_real_error_not_banner(monkeypatch):
    from app.modules.external_scanners import engines

    out = ("        ___\n       __H__\n[10:00:01] [INFO] testing connection to the target URL\n"
           "[10:00:09] [INFO] testing 'AND boolean-based blind'\n"
           "[10:03:00] [CRITICAL] unable to connect to the target URL ('Connection reset by peer')\n")

    async def fake_stream(*args, **kwargs):
        return 1, out, "", "FAILED", 5.0, None

    async def fake_preflight(*args, **kwargs):
        return True, None

    async def fake_version(*args, **kwargs):
        return "test"

    monkeypatch.setattr(engines.settings, "ENABLE_SQLMAP", True)
    monkeypatch.setattr(engines, "_available", lambda _b: True)
    monkeypatch.setattr(engines, "_binary_version", fake_version)
    monkeypatch.setattr(engines, "_preflight", fake_preflight)
    monkeypatch.setattr(engines, "_run_process_streaming", fake_stream)
    result = await engines.run_sqlmap("http://lab.local/search?q=1", safe_mode="safe", timeout_seconds=30)

    assert result["status"] == "FAILED"
    assert "lost the connection" in result["reason"]
    assert "Connection reset by peer" in result["reason"]
    assert "__H__" not in result["reason"]
