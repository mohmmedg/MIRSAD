"""JSON/DB safety helpers for scan snapshots.

PostgreSQL JSON/JSONB text values reject the NUL character (\u0000). Scan
engines can legitimately encounter arbitrary response bytes, so sanitize
recursively at the persistence boundary instead of weakening scanners.
"""
from __future__ import annotations
from typing import Any


def sanitize_json(value: Any) -> Any:
    """Return a JSON-safe copy while preserving normal Unicode content.

    PostgreSQL cannot store the NUL code point in text/json values. Remove
    only NUL; keep all other valid Unicode/control characters intact. Bytes
    are decoded losslessly where possible and represented as text otherwise.
    """
    if isinstance(value, dict):
        return {str(k): sanitize_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize_json(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").replace("\x00", "")
    if isinstance(value, str):
        return value.replace("\x00", "")
    return value
