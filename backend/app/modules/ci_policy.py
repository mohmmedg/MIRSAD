from dataclasses import dataclass

@dataclass(frozen=True)
class CIPolicy:
    critical_fail: int = 0
    high_fail: int = 3
    medium_warn: int = 0

    def evaluate(self, findings):
        counts={s:sum(1 for f in findings if f.severity==s) for s in ("Critical","High","Medium","Low","Info")}
        failures=[]; warnings=[]
        if counts["Critical"] > self.critical_fail: failures.append(f"Critical findings: {counts['Critical']} > {self.critical_fail}")
        if counts["High"] > self.high_fail: failures.append(f"High findings: {counts['High']} > {self.high_fail}")
        if counts["Medium"] > self.medium_warn: warnings.append(f"Medium findings: {counts['Medium']}")
        return {"passed": not failures, "exit_code": 0 if not failures else 1, "counts": counts, "failures": failures, "warnings": warnings}
