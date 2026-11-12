import hashlib
import re
from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl
from app.modules.risk_engine.engine import assess
from app.schemas.platform import CorrelatedFinding, NormalizedFinding

def _norm(value: str | None) -> str:
    return " ".join((value or "").strip().lower().split())

def _origin(value: str | None) -> str:
    """Return a stable origin for controls shared across paths on one target."""
    raw = _norm(value)
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return raw

def _route_identity(value: str | None) -> str:
    raw = _norm(value)
    p = urlsplit(raw)
    if not (p.scheme and p.netloc):
        return raw
    # Stable grouping across the same attackable route without including
    # secret query values or incidental numeric/UUID object identifiers.
    path = re.sub(r"(?<=/)[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "{id}", p.path, flags=re.I)
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", path)
    names = sorted({k.lower() for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    query = urlencode([(k, "*") for k in names])
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path or "/", query, ""))


def finding_fingerprint(f: NormalizedFinding) -> str:
    rule=_norm(getattr(f,"rule_id",None) or f.title)
    vulnerability_class=_norm((getattr(f,"cwe",None) or {}).get("id") if getattr(f,"cwe",None) else None) or _norm(getattr(f,"category",None))
    asset=_norm(f.affected_asset); method=_norm(getattr(f,"method",None)); parameter=_norm(f.parameter); location=_norm(f.location)
    shared_control = rule.startswith(("web-header-config-", "web-cors-", "web-server-disclosure", "web-cookie-"))
    # Header/CORS/cookie controls can deduplicate across paths, but never across
    # different hosts. The old empty key merged observations from unrelated
    # targets into one report finding.
    identity_asset = _origin(asset) if shared_control else _route_identity(asset)
    raw="|".join([identity_asset,method,parameter,location,rule,vulnerability_class])
    return hashlib.sha256(raw.encode()).hexdigest()

def _source(f: NormalizedFinding) -> dict:
    return {"engine":f.source_module,"tool_version":f.tool_version,"finding_id":f.finding_id,"rule_template_plugin":f.rule_id,"url":f.affected_asset,"method":getattr(f,"method",None),"parameter":f.parameter,"request":getattr(f,"request",None),"response":getattr(f,"response",None),"payload":getattr(f,"payload",None),"evidence":[e.model_dump(mode="json") for e in f.evidence],"raw_artifact_id":f.raw_artifact_id,"raw_locator":f.raw_locator,"engine_result_id":f.engine_result_id,"execution_id":f.execution_id,"verification_status":f.verification_status,"confirmation_state":f.confirmation_state,"assessment_state":f.assessment_state,"raw_artifact_sha256":f.raw_artifact_sha256,"first_seen":f.first_seen.isoformat() if f.first_seen else None,"last_seen":f.last_seen.isoformat() if f.last_seen else None}

def correlate(findings: list[NormalizedFinding]) -> list[CorrelatedFinding]:
    groups=defaultdict(list)
    for f in findings:
        fp=f.fingerprint or finding_fingerprint(f); f.fingerprint=fp; groups[fp].append(f)
    out=[]
    rank={"VERIFIED":3,"DETECTED":2,"UNVERIFIED":1,"FALSE_POSITIVE":0,"NOT_APPLICABLE":0,"REJECTED":0}
    for group in groups.values():
        # Prefer the observation whose confirmation contract is satisfied when
        # choosing presentation fields.  This never manufactures confirmation:
        # the gate ran before correlation and scanner agreement alone is ignored.
        primary=max(group,key=lambda x:(getattr(x, "confirmation_state", "CANDIDATE") == "CONFIRMED", assess(x).score,x.confidence,x.finding_id)); r=assess(primary)
        evidence=[]; refs=[]; tags=set(); assets=[]; sources=[]
        for f in group:
            evidence.extend(f.evidence); refs.extend(f.references); tags.update(f.tags); assets.append(f.affected_asset) if f.affected_asset else None; sources.append(_source(f))
        status=max((f.verification_status for f in group),key=lambda x:rank.get(x,0))
        confirmation_state = "CONFIRMED" if any(getattr(f, "confirmation_state", "CANDIDATE") == "CONFIRMED" for f in group) else "CANDIDATE"
        confirmation_reason = ("at_least_one_correlated_observation_has_reproducible_evidence" if confirmation_state == "CONFIRMED"
                               else ";".join(sorted({str(getattr(f, "confirmation_reason", "candidate")) for f in group if getattr(f, "confirmation_reason", None)})) or "candidate")
        if confirmation_state != "CONFIRMED":
            r = assess(primary)  # score is zero for an unconfirmed observation
        primary.assessment_state = ("CONFIRMED" if confirmation_state == "CONFIRMED" else
                                    max((f.assessment_state for f in group), key=lambda x: {
                                        "LIKELY": 4, "INCONCLUSIVE": 3, "NOT_TESTED": 2,
                                        "FALSE_POSITIVE": 1,
                                    }.get(x, 0)))
        primary.risk_contribution=r.score; primary.affected_assets=list(dict.fromkeys(assets)); primary.priority="P1" if r.score>=85 else "P2" if r.score>=60 else "P3" if r.score>=30 else "P4"; primary.observation_count=len(group); primary.evidence_count=len(evidence)
        out.append(CorrelatedFinding(**primary.model_dump(exclude={"evidence","references","tags","risk","related_finding_ids","duplicate_count","source_engines","sources","observations","verification_status","confirmation_state","confirmation_reason"}),verification_status=status,confirmation_state=confirmation_state,confirmation_reason=confirmation_reason,evidence=evidence,references=list(dict.fromkeys(refs)),tags=sorted(tags),risk=r,related_finding_ids=[x.finding_id for x in group if x.finding_id!=primary.finding_id],duplicate_count=len(group),source_engines=list(dict.fromkeys(x.source_module for x in group)),sources=sources,observations=sources))
    return sorted(out,key=lambda x:x.risk.score,reverse=True)


def compute_scan_diff(current: list[CorrelatedFinding], previous: list[dict]) -> dict | None:
    """Compares this scan's findings against the previous scan of the same
    target by fingerprint (the same stable identity used for dedup — see
    finding_fingerprint above) and returns new / resolved / persisting.

    Honest caveat surfaced in the result itself: a fingerprint missing from
    the current scan means it wasn't *detected* this time, which usually
    means it was fixed — but can also mean reduced coverage (a page that
    didn't get crawled this run, a check that failed) produced a false
    "resolved". Coverage percentage from both scans is included so a
    reader can sanity-check that before treating something as fixed.

    Returns None when there's no previous scan to compare against (first
    scan of this target) — a diff against nothing isn't a diff, it's just
    "everything is new", which isn't useful trend information.
    """
    if not previous:
        return None
    prev_by_fp = {f.get("fingerprint"): f for f in previous if f.get("fingerprint")}
    curr_by_fp = {f.fingerprint: f for f in current if f.fingerprint}
    new_fps = set(curr_by_fp) - set(prev_by_fp)
    resolved_fps = set(prev_by_fp) - set(curr_by_fp)
    persisting_fps = set(curr_by_fp) & set(prev_by_fp)
    return {
        "new_findings": [{"finding_id": curr_by_fp[fp].finding_id, "title": curr_by_fp[fp].title, "severity": curr_by_fp[fp].severity} for fp in new_fps],
        "resolved_findings": [{"title": prev_by_fp[fp].get("title"), "severity": prev_by_fp[fp].get("severity")} for fp in resolved_fps],
        "persisting_count": len(persisting_fps),
        "new_count": len(new_fps),
        "resolved_count": len(resolved_fps),
    }
