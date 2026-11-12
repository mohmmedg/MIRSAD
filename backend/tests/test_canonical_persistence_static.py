from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_manager_does_not_repersist_streamed_external_results():
    src = (ROOT / "app/core/architecture/manager.py").read_text()
    assert "if payload.get(\"engine_result_id\"):\n                    continue" in src
    assert "payload[\"raw_artifact_ids\"] = artifact_ids" in src
    assert "payload[\"raw_artifact_id\"] = artifact_ids[0]" not in src


def test_worker_has_no_second_canonical_persistence_path():
    src = (ROOT / "app/worker.py").read_text()
    assert "persist_engine_result" not in src


def test_finding_sources_never_guess_first_artifact():
    src = (ROOT / "app/core/canonical_artifacts.py").read_text()
    assert "artifact_ids[0]" not in src
    assert "Never guess an evidence artifact" in src


def test_stream_recorder_updates_existing_engine_result():
    src = (ROOT / "app/core/canonical_artifacts.py").read_text()
    assert "row=db.get(EngineResultRow,self.engine_result_id)" in src
    assert "self.engine_result_id,self.artifact_ids" not in src
