"""Authoritative assessment safety policy.

This module is deliberately small and shared by all active engines.  A caller
cannot make a safe assessment send write requests merely by toggling an old
compatibility flag; the normalized safe_mode is the source of truth.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyPolicy:
    mode: str

    @property
    def allow_write_methods(self) -> bool:
        return self.mode in {"caution", "destructive"}

    @property
    def allow_delete(self) -> bool:
        return self.mode == "destructive"

    @property
    def allow_authentication_probes(self) -> bool:
        return self.mode == "destructive"

    @property
    def allow_stateful_form_probes(self) -> bool:
        return self.mode in {"caution", "destructive"}

    @property
    def allow_intrusive_template_tags(self) -> bool:
        return self.mode == "destructive"

    @property
    def description(self) -> str:
        return {
            "safe": "read-only discovery and non-mutating canaries",
            "caution": "bounded schema-backed POST/PUT/PATCH probes; DELETE and credential probes disabled",
            "destructive": "bounded declared write/delete and authentication probes, requiring explicit operator confirmation",
        }[self.mode]


def policy_for(mode: str | None) -> SafetyPolicy:
    value = str(mode or "safe").strip().lower()
    if value not in {"safe", "caution", "destructive"}:
        raise ValueError("safe_mode must be safe, caution, or destructive")
    return SafetyPolicy(value)
