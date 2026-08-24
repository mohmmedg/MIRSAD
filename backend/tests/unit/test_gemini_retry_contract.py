import pytest
from unittest.mock import AsyncMock, MagicMock

from app.modules.ai_analysis.analyzer import AIAnalyzer, AIAnalyzerResponseError


@pytest.mark.asyncio
@pytest.mark.parametrize("message", ["503 Service Unavailable", "429 Resource Exhausted"])
async def test_gemini_retries_transient_failures(message):
    analyzer = AIAnalyzer()
    analyzer._client = MagicMock()
    analyzer._client.aio.models.generate_content = AsyncMock(
        side_effect=[Exception(message), Exception(message), Exception(message), Exception(message)]
    )
    with pytest.raises(AIAnalyzerResponseError):
        await analyzer._call_gemini([{"source_module": "web", "detail": {"ok": True}}], "en")
    assert analyzer._client.aio.models.generate_content.await_count == 4
