"""Ghauri is the second SQL-injection engine: its output is parsed with the sqlmap parser (colour codes stripped)."""
import asyncio

from app.core.config import settings
from app.modules.external_scanners import engines
from app.modules.external_scanners.engines import EXTERNAL_ENGINE_NAMES, parse_ghauri_output

T = "http://target.test/item?id=1"

# Result block as Ghauri prints it (format from its source; values taken from a real run against PostgreSQL).
BLOCK = """Ghauri identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind (comment)
    Payload: id=1 AND 4564=(SELECT 4564 FROM PG_SLEEP(8))
---
"""


def test_engine_registered_after_sqlmap():
    assert EXTERNAL_ENGINE_NAMES.index("ghauri") == EXTERNAL_ENGINE_NAMES.index("sqlmap") + 1


def test_result_block_becomes_finding():
    f = parse_ghauri_output(BLOCK, T)
    assert len(f) == 1
    assert f[0]["parameter"] == "id" and f[0]["position"] == "GET" and f[0]["type"] == "time-based blind"
    assert f[0]["detected_by"] == "ghauri" and f[0]["cwe"] == "CWE-89" and "Ghauri" in f[0]["name"]


def test_colour_codes_do_not_hide_verdicts():
    ok = "\x1b[32m[INFO]\x1b[0m GET parameter 'q' appears to be 'AND boolean-based blind' injectable\n"
    assert len(parse_ghauri_output(ok, T)) == 1
    retracted = ok + "\x1b[33m[WARNING]\x1b[0m GET parameter 'q' does not seem to be injectable\n"
    assert parse_ghauri_output(retracted, T) == []


def test_not_injectable_output_has_no_findings():
    out = "[WARNING] GET parameter 'id' does not seem to be injectable\n[CRITICAL] all tested parameters do not appear to be injectable.\n"
    assert parse_ghauri_output(out, T) == []


def test_disabled_and_missing_binary(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_GHAURI", False)
    assert asyncio.run(engines.run_ghauri(T, safe_mode="safe", timeout_seconds=30))["status"] == "SKIPPED"
    monkeypatch.setattr(settings, "ENABLE_GHAURI", True)
    monkeypatch.setattr(settings, "GHAURI_BINARY_PATH", "definitely-not-installed-ghauri")
    assert asyncio.run(engines.run_ghauri(T, safe_mode="safe", timeout_seconds=30))["status"] == "UNAVAILABLE"


def test_multi_runner_uses_given_engine(monkeypatch):
    calls = []

    async def fake_runner(url, **kw):
        calls.append(url)
        return {"status": "COMPLETED", "findings": [], "stdout": "", "stderr": ""}

    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *a, **k: [{"url": "http://t/x?q=1", "data": None, "extra_args": [], "label": "GET parameters"}])
    res = asyncio.run(engines.run_sqlmap_multi("http://t", safe_mode="safe", timeout_seconds=1000, runner=fake_runner, tool="ghauri"))
    assert calls == ["http://t/x?q=1"] and res["status"] == "COMPLETED" and "### ghauri target 1/1" in res["stdout"]
