from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_security_event_supports_tenant_scoped_idempotency_lookup():
    source = (ROOT / "app/core/security_events.py").read_text()
    assert "idempotency_key:str|None=None" in source
    assert 'data["_idempotency_key"]' in source
    assert "SecurityEventRow.tenant_id == tenant_id" in source
    assert "SecurityEventRow.event_type == event_type" in source
    assert "SecurityEventRow.target == target" in source
    assert 'SecurityEventRow.data["_idempotency_key"].as_string()' in source
    assert '"created": False' in source


def test_scanner_finding_pipeline_uses_scan_and_finding_identity():
    source = (ROOT / "app/core/finding_pipeline.py").read_text()
    assert 'idempotency_key=(f"scanner.finding:{scan_id}:{finding[\'finding_id\']}" if scan_id else None)' in source
    assert 'if event.get("created") and event.get("alert_created")' in source
