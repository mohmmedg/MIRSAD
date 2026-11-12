"""Deterministic MIRSAD Priority Score (0-100)."""
def priority_score(*, risk_score: float, epss: float = 0.0, in_kev: bool = False,
                   direct_exposure: bool = False, asset_value: float = 0.5) -> float:
    risk = max(0.0, min(100.0, float(risk_score))) / 100.0
    epss = max(0.0, min(1.0, float(epss)))
    value = max(0.0, min(1.0, float(asset_value)))
    signal = 0.45 * risk + 0.20 * epss + 0.15 * float(in_kev) + 0.10 * float(direct_exposure) + 0.10 * value
    return round(signal * 100.0, 1)
