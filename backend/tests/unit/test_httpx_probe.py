import pytest
from app.modules.external_scanners import engines

@pytest.mark.asyncio
async def test_httpx_filters_scope_and_caps(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_HTTPX_PROBE",True)
    monkeypatch.setattr(engines.settings,"HTTPX_MAX_HOSTS",2)
    monkeypatch.setattr(engines,"_available",lambda _: True)
    monkeypatch.setattr(engines,"_validate_new_engine_target",lambda host: (host in {"api.example.com","web.example.com"}, None if host in {"api.example.com","web.example.com"} else "blocked"))
    async def fake(*a,**k):
        return 0,'{"url":"https://api.example.com","status_code":200,"title":"API"}\n',"","COMPLETED",0.1,""
    monkeypatch.setattr(engines,"_run_process_streaming",fake)
    out=await engines.run_httpx_probe(["api.example.com","169.254.169.254","web.example.com","evil.example.net"])
    assert out["hosts"]==["api.example.com","web.example.com"]
    assert out["enrichment"]["api.example.com"]["status_code"]==200

@pytest.mark.asyncio
async def test_httpx_disabled_and_no_accepted(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_HTTPX_PROBE",False)
    assert (await engines.run_httpx_probe(["api.example.com"]))["status"]=="DISABLED"
