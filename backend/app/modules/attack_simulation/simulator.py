"""4.4 - continuous, safe breach-and-attack-simulation (BAS) replay engine.

Deliberately narrow scope, per how much riskier BAS is than every other item
in this batch: given a template-backed finding that was already detected
once, this module **replays the exact same non-destructive check that
produced it** to confirm it is still live. It never invents a new check,
never chains individually-safe checks into a live multi-step exploit, and
never touches anything outside the existing target-scope allowlist.

It works by reusing ``WebScanEngine._verify_template_match`` byte-for-byte -
the same "second independent GET/HEAD/OPTIONS request, same matcher"
function 2.2 already added (and that _run_templates already calls during a
normal scan). BAS adds no new request type; it only calls that existing,
already-scope-checked verification on a schedule instead of once per scan.

Only template-backed findings (tags containing "template", see
normalizer.py's web.template_findings handling) are replayable, since a
template is the only artifact this module can re-run - port/TLS/NSE-derived
findings are out of scope for replay and are filtered out by the caller
(continuous.py's create_bas_replay) before they ever reach this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from app.modules.web_scan.scanner import WebScanEngine

# Hard ceiling on replay checks in a single run, independent of how many
# findings a schedule was created with - a runaway scheduler bug must never
# turn into an unbounded request flood against a real target.
MAX_REPLAY_CHECKS_PER_RUN = 200


@dataclass(frozen=True)
class ReplayTarget:
    """One previously-verified template finding to re-check."""
    finding_id: str
    template_id: str
    url: str
    method: str = "GET"


@dataclass(frozen=True)
class ReplayOutcome:
    finding_id: str
    template_id: str
    url: str
    still_present: bool | None  # None = template missing/replay error, not a security signal either way
    checked_at: str
    reason: str | None = None


async def replay_targets(targets: list[ReplayTarget]) -> list[ReplayOutcome]:
    """Re-run 2.2's verification for each target, capped at
    MAX_REPLAY_CHECKS_PER_RUN. Every target still goes through
    verify_target_in_scope inside _verify_template_match itself - this
    function adds a run-level cap on top, it does not replace that check."""
    targets = targets[:MAX_REPLAY_CHECKS_PER_RUN]
    engine = WebScanEngine()
    templates_by_id = {t.get("id"): t for t in engine._load_templates() if t.get("id")}
    now = datetime.now(timezone.utc).isoformat()

    outcomes: list[ReplayOutcome] = []
    async with httpx.AsyncClient(timeout=engine.timeout) as client:
        for target in targets:
            template = templates_by_id.get(target.template_id)
            if template is None:
                outcomes.append(ReplayOutcome(
                    finding_id=target.finding_id, template_id=target.template_id, url=target.url,
                    still_present=None, checked_at=now, reason="template no longer registered locally",
                ))
                continue
            try:
                still_present = await engine._verify_template_match(client, template, target.url, target.method)
                outcomes.append(ReplayOutcome(
                    finding_id=target.finding_id, template_id=target.template_id, url=target.url,
                    still_present=still_present, checked_at=now,
                ))
            except Exception as exc:
                outcomes.append(ReplayOutcome(
                    finding_id=target.finding_id, template_id=target.template_id, url=target.url,
                    still_present=None, checked_at=now, reason=f"replay error: {exc}",
                ))
    return outcomes


@dataclass
class ReplaySummary:
    total_targets: int
    still_live_count: int
    resolved_count: int  # was matched before, no longer matches - a real remediation signal
    unknown_count: int
    outcomes: list[ReplayOutcome] = field(default_factory=list)


def summarize_replay(outcomes: list[ReplayOutcome]) -> ReplaySummary:
    """Roll individual finding replays up to one run-level summary, so a
    schedule's notification/history can show one still-live/resolved/unknown
    status instead of one line per finding."""
    still_live = sum(1 for o in outcomes if o.still_present is True)
    resolved = sum(1 for o in outcomes if o.still_present is False)
    unknown = sum(1 for o in outcomes if o.still_present is None)
    return ReplaySummary(
        total_targets=len(outcomes), still_live_count=still_live,
        resolved_count=resolved, unknown_count=unknown, outcomes=outcomes,
    )
