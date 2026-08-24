from app.schemas.platform import NormalizedFinding, RiskAssessment

# Informational observations are useful in reports but must not contribute to
# the security risk score.
WEIGHTS={"Critical":1.0,"High":0.78,"Medium":0.52,"Low":0.28,"Info":0.0}

def assess(f: NormalizedFinding) -> RiskAssessment:
    base=WEIGHTS.get(f.severity,0.0)*100
    evidence=min(1.0, max(0.0,f.confidence))
    corroboration=1.0 if len(f.evidence)>=1 else .6
    score=round(min(100,base*(0.65+0.35*evidence)*corroboration),1)
    return RiskAssessment(score=score,severity=f.severity,confidence=round(evidence,2),factors={"severity_weight":WEIGHTS.get(f.severity,0.0),"confidence":evidence,"evidence":corroboration})

def bundle_score(findings):
    if not findings:return 0.0
    vals=[assess(f).score for f in findings if f.severity != "Info"]
    if not vals:return 0.0
    # Risk is driven by the strongest findings while retaining breadth.
    top=sorted(vals,reverse=True)[:10]
    return round(min(100, sum(top[:3])*0.55 + sum(top[3:])*0.08),1)
