import os
from pathlib import Path
import yaml

from app.core.config import Settings

TOOL_FLAGS = (
    "ENABLE_NUCLEI", "ENABLE_ZAP", "ENABLE_SQLMAP", "ENABLE_FFUF",
    "ENABLE_TESTSSL", "ENABLE_SUBFINDER", "ENABLE_HTTPX_PROBE", "ENABLE_TRIVY",
    "ENABLE_SEMGREP", "ENABLE_GITLEAKS", "ENABLE_TRUFFLEHOG",
    "ENABLE_SOURCE_INTELLIGENCE", "ENABLE_SOURCE_MAP_ANALYSIS", "ENABLE_PLAYWRIGHT",
    "ENABLE_ADVANCED_SECURITY",
)

def test_all_scanner_detector_defaults_enabled(monkeypatch):
    for key in (*TOOL_FLAGS, "ENABLE_LEGACY_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    settings = Settings(_env_file=None)
    for key in TOOL_FLAGS:
        assert getattr(settings, key) is True, key
    assert settings.ENABLE_LEGACY_API_KEY is False

def test_compose_defaults_are_true_without_reading_env_files():
    root = Path(__file__).resolve().parents[2]
    for name in ("docker-compose.yml", "docker-compose.production.yml"):
        data = yaml.safe_load((root.parent / name).read_text())
        worker = data["services"]["worker"]["environment"]
        for key in TOOL_FLAGS:
            assert str(worker[key]).endswith(":-true}"), (name, key, worker.get(key))


def test_external_engine_fanout_is_conservative_by_default(monkeypatch):
    monkeypatch.delenv("EXTERNAL_ENGINE_PARALLELISM", raising=False)
    settings = Settings(_env_file=None)
    assert settings.EXTERNAL_ENGINE_PARALLELISM == 2

