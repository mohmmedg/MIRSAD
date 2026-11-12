from app.core.config import Settings, MIN_TOOL_TIMEOUT_SECONDS
from app.core.job_manager import _apply_task_counts


def test_stale_low_timeouts_are_raised_to_two_hours(monkeypatch):
    for k, v in {"EXTERNAL_DAST_TIMEOUT_SECONDS": "5400", "ADVANCED_SECURITY_TIMEOUT_SECONDS": "900",
                 "SOURCE_TOOL_TIMEOUT_SECONDS": "900", "EXTERNAL_DEEP_TIMEOUT_SECONDS": "1800"}.items():
        monkeypatch.setenv(k, v)
    s = Settings()
    for name in ("DEFAULT_SCAN_TIMEOUT_SECONDS", "EXTERNAL_DAST_TIMEOUT_SECONDS", "EXTERNAL_DEEP_TIMEOUT_SECONDS",
                 "EXTERNAL_EVIDENCE_COLLECTION_TIMEOUT_SECONDS", "ADVANCED_SECURITY_TIMEOUT_SECONDS",
                 "SOURCE_TOOL_TIMEOUT_SECONDS", "TESTSSL_TIMEOUT_SECONDS", "TRIVY_TIMEOUT_SECONDS"):
        assert getattr(s, name) >= MIN_TOOL_TIMEOUT_SECONDS, name


def test_higher_timeouts_are_respected(monkeypatch):
    monkeypatch.setenv("EXTERNAL_DAST_TIMEOUT_SECONDS", "14400")
    assert Settings().EXTERNAL_DAST_TIMEOUT_SECONDS == 14400


def test_task_counter_counts_all_terminal_states():
    stages = [{"status": s} for s in ["completed"] * 18 + ["skipped"] * 6 + ["partial"] * 2 + ["failed"]]
    meta = {}
    _apply_task_counts(meta, stages)
    assert meta["completed_tasks"] == 27
    assert meta["task_breakdown"]["skipped"] == 6 and meta["task_breakdown"]["failed"] == 1
    stages.append({"status": "running"})
    _apply_task_counts(meta, stages)
    assert meta["completed_tasks"] == 27
