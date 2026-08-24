from collections import defaultdict
from app.modules.risk_engine.engine import assess
from app.schemas.platform import CorrelatedFinding, NormalizedFinding

def correlate(findings: list[NormalizedFinding]) -> list[CorrelatedFinding]:
    groups=defaultdict(list)
    for f in findings:
        key=(f.title.lower().strip(), (f.affected_asset or "").lower().strip())
        groups[key].append(f)
    out=[]
    for group in groups.values():
        primary=max(group,key=lambda x: (assess(x).score,x.confidence))
        r=assess(primary)
        evidence=[]
        refs=[]
        tags=set()
        for f in group:
            evidence.extend(f.evidence); refs.extend(f.references); tags.update(f.tags)
        out.append(CorrelatedFinding(**primary.model_dump(exclude={"evidence","references","tags"}), evidence=evidence[:12], references=list(dict.fromkeys(refs)), tags=sorted(tags), risk=r, related_finding_ids=[x.finding_id for x in group if x.finding_id!=primary.finding_id], duplicate_count=len(group)))
    return sorted(out,key=lambda x:x.risk.score,reverse=True)
