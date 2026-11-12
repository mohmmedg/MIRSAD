"""Deprecated standalone CI policy dataclass.

Kept only for backward compatibility with any external code importing
CIPolicy directly. All actual gate logic now lives in
app.modules.compliance.ci_gate - this class builds the same `policy` dict
compliance.ci_gate() expects and delegates to it, instead of maintaining a
second, slightly different severity-threshold comparison (2.4 unification).
"""
from dataclasses import dataclass

from app.modules import compliance


@dataclass(frozen=True)
class CIPolicy:
    critical_fail: int = 0
    high_fail: int = 3
    medium_warn: int = 0

    def evaluate(self, findings):
        # Accept either dicts/pydantic models (what compliance.normalize_findings
        # already handles) or plain objects exposing `.severity`.
        as_dicts = [
            f if isinstance(f, dict) or hasattr(f, "model_dump") else {"severity": getattr(f, "severity", "Info")}
            for f in findings
        ]
        result = compliance.ci_gate(
            as_dicts,
            policy={
                "critical_fail": self.critical_fail,
                "high_fail": self.high_fail,
                # ci_gate's Medium threshold is a fail-limit, not a warn-only
                # count like this class's medium_warn used to be. A very high
                # limit preserves the old "never fails on Medium" behavior
                # while the true Medium count is still surfaced below.
                "medium_fail": 10**9,
            },
        )
        return {
            "passed": result["passed"],
            "exit_code": result["exit_code"],
            "counts": result["counts"],
            "failures": result["failures"],
            "warnings": [f"Medium findings: {result['counts']['Medium']}"] if result["counts"]["Medium"] > self.medium_warn else [],
        }
