"""Regression test for the /platform/scan (synchronous full assessment)
endpoint that used to have NO duration cap at all.

Before the fix, `full_scan()` called `manager.run(body)` directly with no
`asyncio.wait_for`, unlike the async job path (`job_manager._execute`,
`worker.py`) which already respected `max_scan_duration_minutes`. A slow
scan (e.g. a target with many discovered subdomains, each re-running
web+network+api) could run indefinitely with nothing server-side to stop
it — matching a real report of a "full assessment" running 2+ hours without
finishing or stopping.
"""
import asyncio

import pytest
from fastapi import HTTPException

from app.api.routes import platform
from app.schemas.platform import FullScanRequest


def test_full_scan_times_out_per_policy(monkeypatch):
    # full_scan() calls scan_timeout_seconds(), not scan_policy() directly -
    # patch the actual dependency (patching scan_policy alone is a no-op
    # here since scan_timeout_seconds calls its *own* module-local
    # scan_policy reference in app.core.policy_enforcement, not the one
    # re-exported into this module's namespace).
    monkeypatch.setattr(platform, "scan_timeout_seconds", lambda tenant_id: 0.6)

    async def _hang(body):
        await asyncio.sleep(5)
        raise AssertionError("should have been cancelled by the timeout")

    async def _noop_admission(tenant_id):
        return None

    monkeypatch.setattr(platform.manager, "run", _hang)
    monkeypatch.setattr(platform, "enforce_scan_admission", _noop_admission)
    # full_scan() now requires a tenant_id (multi-tenancy, added after this test) and raises
    # 403 "Tenant context required" before ever reaching scan_timeout_seconds()/manager.run().
    # Neutralize tenant resolution the same way enforce_scan_admission already is above - this
    # test is about the timeout wiring, not tenant resolution.
    monkeypatch.setattr(platform, "_require_tenant_id", lambda: "test-tenant")

    body = FullScanRequest(target="https://example.test")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(platform.full_scan(request=None, body=body))
    assert exc.value.status_code == 504


def test_full_scan_completes_normally_within_policy(monkeypatch):
    monkeypatch.setattr(platform, "scan_timeout_seconds", lambda tenant_id: 30 * 60)

    async def _fast(body):
        return {"ok": True}

    async def _noop_admission(tenant_id):
        return None

    monkeypatch.setattr(platform.manager, "run", _fast)
    monkeypatch.setattr(platform, "enforce_scan_admission", _noop_admission)
    monkeypatch.setattr(platform, "_require_tenant_id", lambda: "test-tenant")

    body = FullScanRequest(target="https://example.test")
    result = asyncio.run(platform.full_scan(request=None, body=body))
    assert result == {"ok": True}
