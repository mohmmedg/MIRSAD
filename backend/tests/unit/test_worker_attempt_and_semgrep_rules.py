"""Regressions found in the 2026-10-31 production logs."""
from pathlib import Path

import pytest
import yaml

from app.core.database import JobRow, session_scope_sync
from app.core.job_manager import JobManager


@pytest.mark.asyncio
@pytest.mark.parametrize("count_attempt,expected", [(True, 2), (False, 1)])
async def test_worker_attempt_is_counted_once(count_attempt, expected):
    """worker._load already counts the attempt; start_execution must not count it again,
    otherwise `row.attempt_count > attempt` skips every finalize as a 'stale attempt'."""
    job = await JobManager().create("full", "example.com", start=False, payload={"target": "example.com"})
    with session_scope_sync() as db:
        db.get(JobRow, job.job_id).attempt_count = 1
    job.start_execution(count_attempt=count_attempt)
    with session_scope_sync() as db:
        assert db.get(JobRow, job.job_id).attempt_count == expected


def test_semgrep_rules_use_only_valid_languages():
    """`javascriptreact` is not a Semgrep language: it made semgrep-core exit 8 (RuleParseError)."""
    rules = Path(__file__).parents[2] / "app/modules/external_scanners/rules/mirsad-javascript.yml"
    for rule in yaml.safe_load(rules.read_text(encoding="utf-8"))["rules"]:
        assert set(rule["languages"]) <= {"javascript", "typescript"}, rule["id"]
