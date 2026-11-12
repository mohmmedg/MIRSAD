"""Authoritative, pure terminal-state classification for scanner stages.

An unexecuted detector and an executed detector that failed are *different*.
This module is shared by the web scanner, assessment manager, and worker to
avoid divergent status classifications across API, UI and persisted snapshots.
"""
from __future__ import annotations

from typing import Any, Iterable

INACTIVE = {"DISABLED", "SKIPPED", "UNAVAILABLE", "NOT_INSTALLED", "NOT_CONFIGURED", "NOT_TESTED"}
BAD = {"FAILED"}
PARTIAL = {"PARTIAL", "TIMEOUT", "BUDGET_EXHAUSTED", "CANCELLED"}


def _state(payload: Any) -> str:
    return str(payload.get("status") or "NOT_TESTED").upper() if isinstance(payload, dict) else "NOT_TESTED"


def external_stage_status(results: dict[str, dict], tool_names: Iterable[str]) -> tuple[str, str]:
    names = list(tool_names)
    unavailable = [name for name in names if _state(results.get(name)) in INACTIVE]
    enabled = [name for name in names if name not in unavailable]
    failed = [name for name in enabled if _state(results.get(name)) in BAD]
    partial = [name for name in enabled if _state(results.get(name)) in PARTIAL or
               _state(results.get(name)) not in (BAD | {"COMPLETED"} | PARTIAL)]
    completed = [name for name in enabled if _state(results.get(name)) == "COMPLETED"]
    if not enabled:
        return "skipped", "; ".join(
            f"{name}: {(results.get(name) or {}).get('reason') or _state(results.get(name))}"
            for name in unavailable
        ) or "No external detectors were run"
    if len(failed) == len(enabled):
        return "failed", f"All {len(enabled)} enabled external detector(s) failed: {', '.join(failed)}"
    if failed or partial:
        return "partial", (f"{len(completed)}/{len(enabled)} external detectors completed; "
                           f"partial={','.join(partial) or '-'}, failed={','.join(failed) or '-'}")
    return "completed", f"{len(completed)}/{len(enabled)} external detectors completed"


def web_terminal_status(current: str, external_scanners: dict | None, source_intelligence: dict | None) -> str:
    current = str(getattr(current, "value", current) or "partial").lower()
    if current in {"failed", "cancelled"}:
        return "failed"
    if current not in {"completed", "partial"}:
        return "partial"
    if current == "partial":
        return current
    if isinstance(source_intelligence, dict) and source_intelligence.get("enabled", True):
        if str(source_intelligence.get("status", "")).upper() in BAD | PARTIAL:
            return "partial"
    if external_scanners:
        stage, _ = external_stage_status(external_scanners, external_scanners.keys())
        if stage in {"failed", "partial", "skipped"}:
            return "partial"
    return "completed"


def verification_stage_status(state: str, confirmation: dict | None) -> str:
    """A verifier is incomplete while any candidate still needs evidence."""
    state = str(state or "NOT_TESTED").upper()
    if state in {"FAILED", "TIMEOUT", "BUDGET_EXHAUSTED"}:
        return state
    if (confirmation or {}).get("candidates", 0):
        return "PARTIAL"
    return state


def subdomain_assessment_status(rows: list[dict]) -> str:
    """Aggregate per-host test outcomes, without hiding a failed child check."""
    if not rows:
        return "NOT_TESTED"
    executed = []
    for row in rows:
        status = str(row.get("status") or "").upper()
        if status in {"FAILED", "SKIPPED_SCOPE"}:
            executed.append(status)
        executed.extend(str(s).upper() for s in (row.get("tests") or {}).values()
                        if str(s).upper() not in {"NOT_SELECTED", "SKIPPED", "DISABLED"})
    if not executed:
        return "NOT_TESTED"
    if all(s in {"FAILED", "TIMEOUT", "BUDGET_EXHAUSTED"} for s in executed):
        return "FAILED"
    if any(s not in {"COMPLETED"} for s in executed):
        return "PARTIAL"
    return "COMPLETED"
