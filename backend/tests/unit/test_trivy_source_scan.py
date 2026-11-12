import pytest
from app.modules.external_scanners import engines

@pytest.mark.asyncio
async def test_trivy_parses_vulnerabilities_and_misconfigs(monkeypatch, tmp_path):
    monkeypatch.setattr(engines.settings,"ENABLE_TRIVY",True)
    monkeypatch.setattr(engines,"_available",lambda _: True)
    # run_trivy_source_scan() (engines.py:1529-1531) also requires a trivy.db under
    # TRIVY_CACHE_DIR before it will invoke the binary at all, independent of the
    # _available() binary-on-PATH check above - mock a cache dir with a (fake) DB file
    # present so this test exercises the actual scan/parse path instead of bailing out
    # UNAVAILABLE on "Trivy vulnerability DB is unavailable".
    (tmp_path / "trivy.db").write_bytes(b"")
    monkeypatch.setattr(engines.settings,"TRIVY_CACHE_DIR",str(tmp_path))
    monkeypatch.setattr(engines,"_write_source_snapshot",lambda files: ("/tmp/mirsad-test-root",{}))
    async def fake(*a,**k):
        payload={"Results":[{"Target":"package.json","Vulnerabilities":[{"VulnerabilityID":"CVE-TEST","Severity":"HIGH","PkgName":"demo","InstalledVersion":"1","FixedVersion":"2"}],"Misconfigurations":[{"ID":"MISCONF-1","Severity":"MEDIUM","Title":"Bad setting"}]}]}
        return 0,__import__('json').dumps(payload),"","COMPLETED",0.1,""
    monkeypatch.setattr(engines,"_run_process_streaming",fake)
    monkeypatch.setattr(engines.shutil,"rmtree",lambda *a,**k: None)
    out=await engines.run_trivy_source_scan([("package.json","{}")])
    assert out["status"]=="COMPLETED"
    assert {x["category"] for x in out["findings"]}=={"dependency-vulnerability","misconfiguration"}

@pytest.mark.asyncio
async def test_trivy_no_source_is_not_tested(monkeypatch):
    monkeypatch.setattr(engines.settings,"ENABLE_TRIVY",True)
    monkeypatch.setattr(engines,"_available",lambda _: True)
    out=await engines.run_trivy_source_scan([])
    assert out["status"]=="NOT_TESTED"
