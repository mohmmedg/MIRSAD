import json
import pytest
from app.modules.external_scanners import engines

def test_parse_testssl_flat_and_filters_ok_info():
    data=[
      {"id":"TLS1","severity":"OK","finding":"TLS 1.3 supported"},
      {"id":"BEAST","severity":"HIGH","finding":"Legacy CBC weakness"},
      {"id":"INFO","severity":"INFO","finding":"server banner"},
    ]
    out=engines.parse_testssl_json(data)
    assert len(out)==1 and out[0]["severity"]=="High" and out[0]["category"]=="tls-configuration"

def test_parse_testssl_nested():
    out=engines.parse_testssl_json({"scanResult":[{"findingName":"TLS","severity":"MEDIUM","result":"weak config"}]})
    assert out[0]["name"]=="TLS" and out[0]["severity"]=="Medium"

@pytest.mark.asyncio
async def test_testssl_http_not_tested(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_TESTSSL",True)
    monkeypatch.setattr(engines,"_available",lambda _: True)
    out=await engines.run_testssl("http://127.0.0.1:8000")
    assert out["status"]=="NOT_TESTED"

@pytest.mark.asyncio
async def test_testssl_disabled_and_missing(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_TESTSSL",False)
    assert (await engines.run_testssl("https://127.0.0.1"))["status"]=="DISABLED"
    monkeypatch.setattr(engines.settings,"ENABLE_TESTSSL",True)
    monkeypatch.setattr(engines,"_available",lambda _: False)
    # "NOT_INSTALLED" was the legacy name for this state; engines.py:78 (LEGACY_STATE_MAP)
    # confirms the codebase has since standardized on "UNAVAILABLE" and every binary-missing
    # branch in engines.py (sqlmap, zap, nuclei, ffuf, testssl, trivy, ...) returns it directly.
    assert (await engines.run_testssl("https://127.0.0.1"))["status"]=="UNAVAILABLE"

@pytest.mark.asyncio
async def test_testssl_rejects_dash_host(monkeypatch):
    # parser-level argv invariant: host validation rejects option-like names. Force the binary
    # "present" so this exercises the dash-host check itself (engines.py:551) deterministically -
    # without the mock this test's outcome depended on whether testssl.sh happens to be
    # installed on whatever machine runs it (UNAVAILABLE if absent, FAILED if present).
    monkeypatch.setattr(engines,"_available",lambda _: True)
    out=await engines.run_testssl("https://-bad.example")
    assert out["status"]=="FAILED"
