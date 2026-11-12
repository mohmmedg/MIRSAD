"""Loads compliance controls from YAML framework files instead of a hard-coded
Python list. Each file under frameworks/ maps to exactly one `framework`.

Kept deliberately small and defensive: a malformed or missing YAML file must
never crash startup - it should just contribute zero controls and be logged,
since compliance is a mapping/reporting layer and must not become a new
single point of failure for the rest of the platform.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

FRAMEWORKS_DIR = Path(__file__).resolve().parent / "frameworks"


@dataclass(frozen=True)
class Control:
    control_id: str
    framework: str
    title: str
    description: str
    tags: tuple[str, ...] = ()
    max_severity: str = "Low"


def _load_one(path: Path) -> list[Control]:
    try:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        logger.exception("compliance: failed to parse framework file %s", path)
        return []
    framework = str(raw.get("framework") or path.stem)
    out: list[Control] = []
    for entry in raw.get("controls") or []:
        try:
            out.append(
                Control(
                    control_id=str(entry["control_id"]),
                    framework=framework,
                    title=str(entry.get("title", "")),
                    description=str(entry.get("description", "")),
                    tags=tuple(str(t) for t in (entry.get("tags") or [])),
                    max_severity=str(entry.get("max_severity", "Low")),
                )
            )
        except Exception:
            logger.exception("compliance: skipping malformed control in %s", path)
    return out


@lru_cache(maxsize=1)
def load_controls() -> tuple[Control, ...]:
    """Loads and caches every *.yaml/*.yml file under frameworks/. Cached
    because these files are static deployment artifacts, not runtime state;
    call load_controls.cache_clear() in tests that swap the directory."""
    if not FRAMEWORKS_DIR.is_dir():
        logger.warning("compliance: frameworks directory missing at %s", FRAMEWORKS_DIR)
        return ()
    controls: list[Control] = []
    for path in sorted(FRAMEWORKS_DIR.glob("*.yaml")) + sorted(FRAMEWORKS_DIR.glob("*.yml")):
        controls.extend(_load_one(path))
    return tuple(controls)
