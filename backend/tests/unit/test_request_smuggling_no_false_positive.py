import pytest
from app.core.config import settings
from app.modules.advanced_security import AdvancedSecurityEngine


class _Budget:
    async def acquire_external(self, *_a): pass
    def release_external(self): pass


@pytest.mark.asyncio
async def test_connection_refused_is_not_a_finding(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SSRF_RISK_TARGETS", True)
    monkeypatch.setattr(settings, "ENFORCE_TARGET_SCOPE", False)
    eng = AdvancedSecurityEngine()
    out = await eng._request_smuggling("http://127.0.0.1:9", "destructive", True, _Budget())
    assert out["findings"] == []
    assert out["status"] == "NOT_TESTED"
