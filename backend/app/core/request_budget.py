"""Per-assessment HTTP request budget, rate and concurrency enforcement.

The budget is shared by the web/API engines of one assessment.  It counts
actual outbound HTTP attempts at the transport boundary, so redirects,
active checks, template probes and API discovery all consume the same budget.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from collections import deque

import httpx


def _trace_http(request, response, body, duration_ms, error):
    try:
        from app.core import execution_trace as t
        t.emit_http(method=request.method, url=str(request.url), request_headers=request.headers,
                    request_body=(request.content if hasattr(request, 'read') and getattr(request, '_content', None) is not None else None),
                    status=getattr(response, 'status_code', None), reason=getattr(response, 'reason_phrase', '') or '',
                    response_headers=getattr(response, 'headers', None), response_body=body,
                    response_content_type=(response.headers.get('content-type', '') if response is not None else ''),
                    duration_ms=duration_ms, error=error, source='httpx')
    except Exception:
        pass


class RequestBudgetExceeded(RuntimeError):
    """Raised before an outbound HTTP request when the scan budget is exhausted."""


@dataclass
class _PhaseLimit:
    maximum: int
    used: int = 0


# Context-local allowance: parallel tasks in one phase inherit the same mutable
# counter; unrelated external engines never share the phase's allowance.
_phase_limit: ContextVar[_PhaseLimit | None] = ContextVar("mirsad_request_phase", default=None)


class RequestBudget:
    def __init__(self, max_requests: int = 5000, requests_per_second: int = 5, max_concurrency: int = 4):
        self.max_requests = max(1, int(max_requests))
        self.requests_per_second = max(1, int(requests_per_second))
        self.max_concurrency = max(1, int(max_concurrency))
        self._used = 0
        self._lock = asyncio.Lock()
        self._rate_times: deque[float] = deque()
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._started = time.monotonic()
        self._by_kind: dict[str, int] = {"http": 0}

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self._used)

    @contextmanager
    def phase_limit(self, maximum: int):
        limit = _PhaseLimit(maximum=max(1, int(maximum)))
        token = _phase_limit.set(limit)
        try:
            yield limit
        finally:
            _phase_limit.reset(token)

    async def acquire(self) -> None:
        await self._semaphore.acquire()
        try:
            while True:
                async with self._lock:
                    if self._used >= self.max_requests:
                        raise RequestBudgetExceeded(
                            f"HTTP request budget exhausted ({self.max_requests} attempts)"
                        )
                    phase = _phase_limit.get()
                    if phase is not None and phase.used >= phase.maximum:
                        raise RequestBudgetExceeded(
                            f"phase request budget exhausted ({phase.maximum} attempts)"
                        )
                    now = time.monotonic()
                    while self._rate_times and now - self._rate_times[0] >= 1.0:
                        self._rate_times.popleft()
                    if len(self._rate_times) < self.requests_per_second:
                        self._rate_times.append(now)
                        self._used += 1
                        if phase is not None:
                            phase.used += 1
                        self._by_kind["http"] = self._by_kind.get("http", 0) + 1
                        return
                    wait_for = max(0.01, 1.0 - (now - self._rate_times[0]))
                await asyncio.sleep(wait_for)
        except Exception:
            self._semaphore.release()
            raise


    async def acquire_external(self, kind: str = "external") -> None:
        """Reserve one outbound non-HTTP-client operation under the same budget.

        Nmap, DNS/TLS sockets, external intelligence calls and protocol probes do
        not pass through httpx's transport, so they explicitly consume the same
        global budget here. The reservation also shares the RPS/concurrency gate.
        """
        await self.acquire()
        async with self._lock:
            self._by_kind["http"] = max(0, self._by_kind.get("http", 0) - 1)
            self._by_kind[kind] = self._by_kind.get(kind, 0) + 1

    def release_external(self) -> None:
        self.release()

    def release(self) -> None:
        self._semaphore.release()

    def snapshot(self) -> dict[str, int | float]:
        elapsed = max(0.001, time.monotonic() - self._started)
        return {
            "max_requests": self.max_requests,
            "used": self._used,
            "remaining": self.remaining,
            "requests_per_second": self.requests_per_second,
            "max_concurrency": self.max_concurrency,
            "elapsed_seconds": round(elapsed, 2),
            "average_requests_per_second": round(self._used / elapsed, 2),
            "by_kind": dict(self._by_kind),
        }


class BudgetTransport(httpx.AsyncBaseTransport):
    """httpx transport wrapper that enforces one shared RequestBudget."""

    def __init__(self, budget: RequestBudget, **transport_kwargs):
        self.budget = budget
        self._transport = httpx.AsyncHTTPTransport(**transport_kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await self.budget.acquire()
        started = time.monotonic()
        try:
            response = await self._transport.handle_async_request(request)
        except Exception as exc:
            _trace_http(request, None, None, (time.monotonic() - started) * 1000, f"{type(exc).__name__}: {exc}")
            raise
        finally:
            self.budget.release()
        body = None
        try:
            ctype = response.headers.get("content-type", "")
            clen = int(response.headers.get("content-length") or 0)
            if (clen == 0 or clen <= 262_144) and any(t in ctype.lower() for t in ("text", "json", "xml", "javascript", "html", "yaml")):
                # Buffer small textual bodies so they can be shown in the live trace.
                # The buffered content stays on the response for the caller.
                await response.aread()
                body = response.content
        except Exception:
            body = None
        _trace_http(request, response, body, (time.monotonic() - started) * 1000, None)
        return response

    async def aclose(self) -> None:
        await self._transport.aclose()



class TargetUnreachableError(RuntimeError):
    """Raised immediately once too many consecutive connection attempts failed."""


class TargetUnhealthyError(TargetUnreachableError):
    """Raised while the target is returning sustained 5xx; traffic is paused, not abandoned."""


class GuardedTransport(httpx.AsyncBaseTransport):
    """BudgetTransport + (1) loopback->Docker-host rewrite + (2) circuit breaker.

    Inside the scanner container 127.0.0.1/localhost is the container itself, so
    crawler-discovered URLs such as http://127.0.0.1:3000/x always failed with
    ConnectTimeout (~60-90 s each, 200+ times in one scan = ~100 min, measured
    2026-10-11). Requests are rewritten to a host alias that really reaches the
    Docker host (original Host header kept), and after ``fail_limit`` consecutive
    connect failures every further request fails instantly instead of waiting.
    """

    _LOOPBACK = {"127.0.0.1", "localhost", "::1"}

    def __init__(self, budget: RequestBudget, *, fail_limit: int | None = None, **transport_kwargs):
        from app.core.config import settings
        self._inner = BudgetTransport(budget, **transport_kwargs)
        self.fail_limit = int(fail_limit if fail_limit is not None else getattr(settings, "TARGET_CONNECT_FAIL_LIMIT", 8))
        self.consecutive_failures = 0
        self.tripped = False
        # Health-aware pause: sustained 5xx means the target is struggling (e.g. OOM restart),
        # so further results would not be a normal test. Half-open after the cooldown.
        self.error_limit = int(getattr(settings, "TARGET_5XX_FAIL_LIMIT", 25))
        self.cooldown = float(getattr(settings, "TARGET_UNHEALTHY_COOLDOWN_SECONDS", 30.0))
        self.consecutive_5xx = 0
        self.unhealthy_until = 0.0
        self.unhealthy_trips = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if time.monotonic() < self.unhealthy_until:
            raise TargetUnhealthyError(
                f"target unhealthy: {self.error_limit} consecutive 5xx responses; traffic paused {self.cooldown:.0f}s")
        if self.tripped:
            raise TargetUnreachableError(
                f"target unreachable: circuit open after {self.fail_limit} consecutive connection failures")
        host = request.url.host
        if host in self._LOOPBACK:
            from app.modules.external_scanners.engines import resolve_loopback_host
            alias = await asyncio.to_thread(resolve_loopback_host, request.url.port)
            original_host_header = request.headers.get("host")
            request.url = request.url.copy_with(host=alias)
            if original_host_header:
                request.headers["host"] = original_host_header
        try:
            response = await self._inner.handle_async_request(request)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            self.consecutive_failures += 1
            if self.consecutive_failures >= self.fail_limit:
                self.tripped = True
            raise
        self.consecutive_failures = 0
        if response.status_code >= 500:
            self.consecutive_5xx += 1
            if self.consecutive_5xx >= self.error_limit:
                self.unhealthy_until = time.monotonic() + self.cooldown
                self.unhealthy_trips += 1
                self.consecutive_5xx = 0
        else:
            self.consecutive_5xx = 0
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()
