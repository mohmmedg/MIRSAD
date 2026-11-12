from pathlib import Path
import yaml


def test_defectdojo_web_and_worker_share_mirsad_sarif_hash_fields():
    root = Path(__file__).resolve().parents[3]
    expected = {
        "MIRSAD Scan (SARIF)": ["title", "cwe", "line", "file_path", "description"]
    }
    for compose_name in ("docker-compose.yml", "docker-compose.production.yml"):
        compose = yaml.safe_load((root / compose_name).read_text(encoding="utf-8"))
        services = compose["services"]
        for service_name in ("defectdojo-uwsgi", "defectdojo-celeryworker"):
            raw = services[service_name]["environment"]["DD_HASHCODE_FIELDS_PER_SCANNER"]
            assert yaml.safe_load(raw) == expected


def test_production_defectdojo_waits_for_postgres_readiness():
    root = Path(__file__).resolve().parents[3]
    compose = yaml.safe_load((root / "docker-compose.production.yml").read_text(encoding="utf-8"))
    postgres = compose["services"]["postgres18"]
    assert "pg_isready -U defectdojo -d defectdojo" in " ".join(postgres["healthcheck"]["test"])
    for service_name in ("defectdojo-uwsgi", "defectdojo-celerybeat", "defectdojo-celeryworker", "defectdojo-initializer"):
        assert compose["services"][service_name]["depends_on"]["postgres18"]["condition"] == "service_healthy"
