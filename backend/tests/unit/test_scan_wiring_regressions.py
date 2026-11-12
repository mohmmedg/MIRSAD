"""Regression tests for the 2026-09-21 scan-breaking wiring bugs."""
import inspect

import pytest

from app.modules.api_security.scanner import APISecurityScanner
from app.modules.web_scan import scanner as web_scanner_module
from app.modules.web_scan.scanner import WebScanEngine


def test_web_scanner_module_imports_resolve_safe_target():
    # was: NameError "name 'resolve_safe_target' is not defined" during web crawl
    assert hasattr(web_scanner_module, "resolve_safe_target")


def test_api_scan_accepts_oob_and_destructive_confirmation():
    params = inspect.signature(APISecurityScanner.scan).parameters
    assert "oob_callback_domain" in params
    assert "destructive_confirmation" in params


def test_web_scan_accepts_destructive_confirmation():
    assert "destructive_confirmation" in inspect.signature(WebScanEngine.scan).parameters


def test_manager_forwards_destructive_confirmation_to_web_and_api():
    import re
    from app.core.architecture import manager
    src = inspect.getsource(manager)
    for call in ("self.web.scan(", "self.api.scan("):
        for m in re.finditer(re.escape(call), src):
            # the argument list of each call must carry the confirmation flag
            depth, k = 0, m.end() - 1
            while True:
                depth += src[k] == "("
                depth -= src[k] == ")"
                if depth == 0:
                    break
                k += 1
            assert "destructive_confirmation=req.destructive_confirmation" in src[m.start():k], call


def test_manager_forwards_scan_profile_and_safe_mode_to_testssl():
    from app.core.architecture import manager
    src = inspect.getsource(manager)
    assert "run_testssl(ext_target, safe_mode=req.safe_mode, scan_profile=req.scan_profile" in src


def test_httpx_stage_reflects_detector_status_instead_of_always_completed():
    from app.core.architecture import manager
    src = inspect.getsource(manager)
    assert 'probe_status = str(probe.get("status") or "FAILED").upper()' in src
    assert '"UNAVAILABLE": "skipped"' in src
    assert 'job.set_stage("httpx_probe", stage_status' in src


def test_source_detector_paths_are_stable_and_never_escape_snapshot(tmp_path):
    from app.modules.external_scanners.engines import _source_snapshot_relative_path

    source = tmp_path / "src" / "main.js"
    source.parent.mkdir()
    source.write_text("const x = 1")
    assert _source_snapshot_relative_path(str(tmp_path), str(source)) == "src/main.js"
    assert _source_snapshot_relative_path(str(tmp_path), "src/main.js") == "src/main.js"
    assert _source_snapshot_relative_path(str(tmp_path), "/etc/passwd") == "passwd"


@pytest.mark.asyncio
async def test_trufflehog_uses_relative_evidence_path_and_cleans_snapshot(monkeypatch):
    import json
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines.settings, "ENABLE_TRUFFLEHOG", True)
    monkeypatch.setattr(engines.settings, "TRUFFLEHOG_BINARY_PATH", "trufflehog")
    monkeypatch.setattr(engines, "_available", lambda _binary: True)
    captured = {}

    async def fake_exec(_binary, _args, _timeout, *, cwd=None):
        captured["root"] = cwd
        payload = {
            "DetectorName": "TestDetector",
            "Raw": "secret-value",
            "SourceMetadata": {"Data": {"Filesystem": str(__import__("pathlib").Path(cwd, "src", "app.js"))}},
            "Verified": False,
        }
        return "COMPLETED", 0, json.dumps(payload) + "\n", ""

    async def fake_version(*_args, **_kwargs):
        return "test-version"

    monkeypatch.setattr(engines, "_run_bounded_exec", fake_exec)
    monkeypatch.setattr(engines, "_binary_version", fake_version)
    result = await engines.run_trufflehog_source_scan([("src/app.js", "const x = 1")])

    assert result["findings"][0]["matched_at"] == "src/app.js"
    assert not __import__("pathlib").Path(captured["root"]).exists()


def test_external_stage_treats_not_tested_detectors_as_skipped():
    from app.core.architecture.manager import external_stage_status

    status, message = external_stage_status({
        "nuclei": {"status": "COMPLETED"},
        "zap": {"status": "COMPLETED"},
        "sqlmap": {"status": "COMPLETED"},
        "ghauri": {"status": "COMPLETED"},
        "ffuf": {"status": "COMPLETED"},
        "testssl": {"status": "NOT_TESTED", "reason": "testssl requires an HTTPS target"},
    })
    assert status == "completed"
    assert "5/5" in message

@pytest.mark.asyncio
async def test_gitleaks_findings_are_completed_and_paths_are_relative(monkeypatch):
    import json
    from pathlib import Path
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines.settings, "ENABLE_GITLEAKS", True)
    monkeypatch.setattr(engines.settings, "GITLEAKS_BINARY_PATH", "gitleaks")
    monkeypatch.setattr(engines, "_available", lambda _binary: True)
    captured = {}

    async def fake_exec(_binary, args, _timeout, *, cwd=None):
        captured["root"] = cwd
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(json.dumps([{
            "Description": "Test secret",
            "RuleID": "generic-api-key",
            "File": str(Path(cwd, "src", "app.js")),
            "Fingerprint": "stable-fingerprint",
        }]))
        return "PARTIAL", 1, "", ""

    async def fake_version(*_args, **_kwargs):
        return "test-version"

    monkeypatch.setattr(engines, "_run_bounded_exec", fake_exec)
    monkeypatch.setattr(engines, "_binary_version", fake_version)
    result = await engines.run_gitleaks_source_scan([("src/app.js", "const x = 'secret'")])

    assert result["status"] == "COMPLETED"
    assert result["exit_code"] == 1
    assert result["findings"][0]["matched_at"] == "src/app.js"
    assert not Path(captured["root"]).exists()

@pytest.mark.asyncio
@pytest.mark.parametrize(("profile", "expect_fast"), [("passive", True), ("quick", True), ("standard", False), ("deep", False), ("maximum", False)])
async def test_testssl_profile_controls_tls_coverage(monkeypatch, profile, expect_fast):
    from app.modules.external_scanners import engines
    from pathlib import Path
    import json

    monkeypatch.setattr(engines.settings, "ENABLE_TESTSSL", True)
    monkeypatch.setattr(engines.settings, "TESTSSL_BINARY_PATH", "testssl.sh")
    monkeypatch.setattr(engines, "_available", lambda _binary: True)
    captured = {}

    async def fake_version(*_args, **_kwargs):
        return "test-version"

    async def fake_process(_binary, args, _timeout, **_kwargs):
        captured["args"] = list(args)
        output = Path(args[args.index("--jsonfile") + 1])
        output.write_text(json.dumps([]))
        return 0, "", "", "COMPLETED", 1, None

    monkeypatch.setattr(engines, "_binary_version", fake_version)
    monkeypatch.setattr(engines, "_run_process_streaming", fake_process)
    # "example.test" is not in this suite's ALLOWED_TARGETS (conftest.py only allow-lists
    # example.com among RFC 2606 reserved domains) -> _validate_new_engine_target() inside
    # run_testssl() rejected it with ScopeViolationError, turning every case here into FAILED
    # regardless of --fast wiring, which is what this test actually exercises. Use the allowed one.
    result = await engines.run_testssl("https://example.com", safe_mode="safe", scan_profile=profile)

    assert result["status"] == "COMPLETED"
    assert ("--fast" in captured["args"]) is expect_fast

@pytest.mark.asyncio
async def test_sqlmap_multi_marks_unstarted_targets_not_tested(monkeypatch):
    from app.modules.external_scanners import engines

    targets = [
        {"url": f"https://example.test/item?id={i}", "data": None, "extra_args": [], "label": f"target-{i}"}
        for i in range(3)
    ]
    monkeypatch.setattr(engines, "select_sqlmap_targets", lambda *_args, **_kwargs: targets)
    clock = iter([100.0, 100.0, 102.0, 102.0])
    monkeypatch.setattr(engines.time, "time", lambda: next(clock, 102.0))

    async def fake_run_sqlmap(*_args, **_kwargs):
        return {"status": "COMPLETED", "findings": [], "stdout": "", "stderr": "", "raw_files": [], "exit_code": 0}

    monkeypatch.setattr(engines, "run_sqlmap", fake_run_sqlmap)
    result = await engines.run_sqlmap_multi(
        "https://example.test", safe_mode="safe", timeout_seconds=1, max_targets=3
    )

    assert result["status"] == "PARTIAL"
    assert [item["status"] for item in result["targets_tested"]] == ["COMPLETED", "NOT_TESTED", "NOT_TESTED"]
    assert "2 target(s) not tested" in result["reason"]


def test_production_worker_build_receives_same_trivy_db_build_arg_as_backend():
    from pathlib import Path

    compose = Path(__file__).resolve().parents[2] / ".." / "docker-compose.production.yml"
    text = compose.resolve().read_text(encoding="utf-8")
    backend = text.split("\n  backend:\n", 1)[1].split("\n  worker:\n", 1)[0]
    worker = text.split("\n  worker:\n", 1)[1]
    expected = "TRIVY_DB_REQUIRED: ${TRIVY_DB_REQUIRED:-false}"
    assert expected in backend
    assert expected in worker
    backend_environment = backend.split("    environment:\n", 1)[1]
    worker_environment = worker.split("    environment:\n", 1)[1]
    assert expected in backend_environment
    assert expected in worker_environment


def test_dockerfile_runs_trivy_cache_guard_for_api_and_worker():
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parents[2] / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")
    assert 'ENTRYPOINT ["/app/scripts/ensure_trivy_db.sh"]' in text


def test_nuclei_template_inventory_detects_missing_and_present_templates(monkeypatch, tmp_path):
    from app.modules.external_scanners import engines

    monkeypatch.setattr(engines, "Path", __import__("pathlib").Path)
    assert engines._nuclei_template_count(tmp_path) == 0
    template = tmp_path / "http" / "test.yaml"
    template.parent.mkdir()
    template.write_text("id: test\ninfo:\n  name: test\n", encoding="utf-8")
    assert engines._nuclei_template_count(tmp_path) == 1


def test_defectdojo_retry_reclaims_stale_running_jobs():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    retry_source = (root / "app" / "integrations" / "defectdojo" / "retry.py").read_text(encoding="utf-8")
    config_source = (root / "app" / "core" / "config.py").read_text(encoding="utf-8")
    assert 'ExternalSyncJobRow.status == "RUNNING"' in retry_source
    assert 'ExternalSyncJobRow.updated_at <= stale_before' in retry_source
    assert "DEFECTDOJO_STALE_JOB_SECONDS: int = 1800" in config_source
    assert "with_for_update(skip_locked=True)" in retry_source



def test_defectdojo_finding_mapping_idempotency_is_scan_scoped():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "app" / "integrations" / "defectdojo" / "retry.py").read_text(encoding="utf-8")
    assert "idem=f\"finding:{job['scan_id']}:" in source
    assert "getattr(f, 'finding_id', fp)" in source


def test_reparse_uses_one_complete_artifact_per_engine_not_chunks_or_stderr():
    from types import SimpleNamespace
    from app.api.routes.platform import _select_reparse_artifacts

    rows = [
        SimpleNamespace(tool="nuclei", kind="stdout"),
        SimpleNamespace(tool="nuclei", kind="stdout_aggregate"),
        SimpleNamespace(tool="nuclei", kind="stderr_aggregate"),
        SimpleNamespace(tool="sqlmap", kind="stdout_aggregate"),
        SimpleNamespace(tool="sqlmap", kind="stderr"),
        SimpleNamespace(tool="ffuf", kind="output"),
        SimpleNamespace(tool="ffuf", kind="stdout_aggregate"),
        SimpleNamespace(tool="zap", kind="report"),
    ]
    selected = _select_reparse_artifacts(rows)
    assert [(row.tool, row.kind) for row in selected] == [
        ("sqlmap", "stdout_aggregate"),
        ("nuclei", "stdout_aggregate"),
        ("ffuf", "output"),
    ]


def test_reparse_falls_back_to_legacy_stdout_artifacts():
    from types import SimpleNamespace
    from app.api.routes.platform import _select_reparse_artifacts

    rows = [SimpleNamespace(tool="nuclei", kind="stderr"),
            SimpleNamespace(tool="nuclei", kind="stdout")]
    assert _select_reparse_artifacts(rows) == [rows[1]]
