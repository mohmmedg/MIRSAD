import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from app.modules.ai_analysis.analyzer import AIAnalyzer, AIAnalyzerResponseError


def _finding():
    ev = SimpleNamespace(evidence="e")
    return SimpleNamespace(finding_id="f1", source_module="web", title="t", severity="High",
                           confidence=0.9, description="d", evidence=[ev], affected_asset="a", references=[])


def _analyzer(side_effect):
    a = AIAnalyzer()
    a._validate_retry_delays = (0, 0, 0)
    a._client = MagicMock()
    a._client.aio.models.generate_content = AsyncMock(side_effect=side_effect)
    return a


@pytest.mark.asyncio
async def test_validate_recovers_after_transient_503():
    ok = SimpleNamespace(text='{"validated": [{"finding_id": "f1", "verdict": "confirmed"}]}')
    a = _analyzer([Exception("503 UNAVAILABLE model overloaded"), Exception("503 UNAVAILABLE"), ok])
    out = await a.validate_findings([_finding()])
    assert out["status"] == "completed"
    assert a._client.aio.models.generate_content.await_count == 3


@pytest.mark.asyncio
async def test_validate_gives_up_after_all_retries():
    a = _analyzer([Exception("503 UNAVAILABLE")] * 4)
    with pytest.raises(AIAnalyzerResponseError):
        await a.validate_findings([_finding()])
    assert a._client.aio.models.generate_content.await_count == 4


@pytest.mark.asyncio
async def test_validate_does_not_retry_permanent_errors():
    a = _analyzer([Exception("400 INVALID_ARGUMENT bad key")])
    with pytest.raises(AIAnalyzerResponseError):
        await a.validate_findings([_finding()])
    assert a._client.aio.models.generate_content.await_count == 1
