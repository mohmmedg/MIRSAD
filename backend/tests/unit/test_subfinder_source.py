import pytest
from app.modules.external_scanners import engines

@pytest.mark.asyncio
async def test_subfinder_jsonl_filters_scope_wildcard_duplicates(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_SUBFINDER",True)
    monkeypatch.setattr(engines,"_available",lambda _: True)
    async def fake(*a,**k):
        out='{"host":"api.example.com"}\n{"host":"api.example.com"}\n{"host":"*.example.com"}\n{"host":"evil.example.net"}\n'
        return 0,out,"","COMPLETED",0.1,""
    monkeypatch.setattr(engines,"_run_process_streaming",fake)
    out=await engines.run_subfinder_source("example.com")
    assert list(out)==["api.example.com"]

@pytest.mark.asyncio
async def test_subfinder_disabled_missing_invalid(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_SUBFINDER",False)
    assert await engines.run_subfinder_source("example.com")=={}
    monkeypatch.setattr(engines.settings,"ENABLE_SUBFINDER",True)
    monkeypatch.setattr(engines,"_available",lambda _: False)
    assert await engines.run_subfinder_source("example.com")=={}
    assert await engines.run_subfinder_source("not a domain")=={}
