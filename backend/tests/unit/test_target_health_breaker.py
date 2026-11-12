"""5xx circuit breaker: sustained server errors pause traffic, then traffic resumes."""
import httpx
import pytest

from app.core.request_budget import GuardedTransport, RequestBudget, TargetUnhealthyError


class _Fake:
    def __init__(self, status): self.status = status; self.calls = 0
    async def handle_async_request(self, request):
        self.calls += 1
        return httpx.Response(self.status, request=request)


async def _get(t):
    return await t.handle_async_request(httpx.Request("GET", "http://203.0.113.5/x"))


async def test_pauses_after_consecutive_5xx_then_resumes():
    t = GuardedTransport(RequestBudget(), fail_limit=8)
    t.error_limit, t.cooldown = 3, 0.05
    fake = _Fake(503); t._inner = fake
    for _ in range(3):
        assert (await _get(t)).status_code == 503
    with pytest.raises(TargetUnhealthyError):
        await _get(t)
    assert fake.calls == 3 and t.unhealthy_trips == 1  # paused request never reached the target
    import asyncio; await asyncio.sleep(0.06)
    fake.status = 200
    assert (await _get(t)).status_code == 200  # half-open: traffic resumes


async def test_non_5xx_resets_counter():
    t = GuardedTransport(RequestBudget(), fail_limit=8)
    t.error_limit = 3
    fake = _Fake(500); t._inner = fake
    await _get(t); await _get(t)
    fake.status = 404; await _get(t)
    fake.status = 500; await _get(t); await _get(t)
    assert t.unhealthy_trips == 0
