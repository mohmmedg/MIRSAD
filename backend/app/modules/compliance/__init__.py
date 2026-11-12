"""Compliance mapping, assessment and SARIF export.

Deterministic findings remain authoritative. Compliance is a control-mapping layer:
finding -> control evidence -> control status. AI is never used to decide pass/fail.

Controls are loaded from YAML files under compliance/frameworks/ (see loader.py)
instead of being hard-coded here, so new frameworks (e.g. regional ones added
for data-sovereignty coverage) are added by dropping in a YAML file, not by
editing this module.

ci_gate() below is now the single source of truth for CI/CD pass-fail
evaluation. The previous standalone app.modules.ci_policy.CIPolicy duplicated
this logic with a slightly different (findings-object-based, no SARIF/coverage)
threshold check; it now delegates here for backward compatibility instead of
re-implementing the comparison.
"""
from __future__ import annotations
from typing import Any
from datetime import datetime, timezone

from .loader import Control, load_controls

SEVERITY_ORDER={"Critical":4,"High":3,"Medium":2,"Low":1,"Info":0}


def controls(framework: str|None=None)->list[Control]:
    return [c for c in load_controls() if not framework or c.framework.lower()==framework.lower()]


def frameworks() -> list[str]:
    """Every distinct framework name currently loaded, for UI framework pickers."""
    seen: list[str] = []
    for c in load_controls():
        if c.framework not in seen:
            seen.append(c.framework)
    return seen


def _finding_dict(f:Any)->dict:
    if hasattr(f,"model_dump"): return f.model_dump(mode="json")
    return f if isinstance(f,dict) else {}

def normalize_findings(findings:Any)->list[dict]:
    if isinstance(findings,dict):
        if "findings" in findings: findings=findings["findings"]
        elif "result" in findings and isinstance(findings["result"],dict): findings=findings["result"].get("findings",[])
    return [_finding_dict(x) for x in (findings or [])]

def _matches(control:Control, f:dict)->bool:
    text=" ".join(str(f.get(k,"")) for k in ("title","description","source_module","affected_asset","remediation"))
    text += " " + " ".join(str(x) for x in f.get("tags",[]) or [])
    low=text.lower()
    if not control.tags: return False
    return any(tag in low for tag in control.tags)

# Maps a control's descriptive tags to the scan-coverage capability keys produced by
# app/core/architecture/manager.py (result.coverage["capabilities"]). This lets
# assess() tell "nothing found because it wasn't tested" (NOT_ASSESSED) apart from
# "tested and genuinely clean" (PASS) - both currently look identical if you only
# look at the absence of matching findings. Tags with no reliable single capability
# (e.g. generic "scanner"/"asm"/"scope") are intentionally left unmapped, which keeps
# the existing findings-only heuristic as the fallback for them.
TAG_TO_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "auth": ("authentication",),
    "authorization": ("authorization",),
    "api": ("api_discovery", "rest_api"),
    "headers": ("security_headers",),
    "web": ("web",),
    "configuration": ("security_headers", "api_discovery"),
    "network": ("network",),
    "dns": ("dns",),
    "asset": ("discovery",),
    "vulnerability": ("vulnerability_verification",),
}
_TESTED_STATES = {"COMPLETED", "PARTIAL", "TESTED"}

def _control_tested(control: Control, coverage: dict[str, Any]) -> bool | None:
    """True/False if coverage confirms the relevant capability was (not) exercised,
    or None when there is no coverage signal for this control's tags at all - in
    which case the caller falls back to the finding-presence heuristic."""
    capabilities = (coverage or {}).get("capabilities") if isinstance(coverage, dict) else None
    if not isinstance(capabilities, dict) or not capabilities:
        return None
    relevant: set[str] = set()
    for tag in control.tags:
        relevant.update(TAG_TO_CAPABILITIES.get(tag, ()))
    known = [capabilities[name] for name in relevant if name in capabilities]
    if not known:
        return None
    return any(str((entry or {}).get("status", "")).upper() in _TESTED_STATES for entry in known)

def assess(findings:Any, framework:str|None=None, coverage: dict[str, Any] | None = None)->dict:
    fs=normalize_findings(findings)
    cs=controls(framework)
    rows=[]
    for c in cs:
        matches=[f for f in fs if _matches(c,f)]
        blocking=[f for f in matches if SEVERITY_ORDER.get(str(f.get("severity","Info")).title(),0)>=SEVERITY_ORDER.get(c.max_severity,1)]
        tested = _control_tested(c, coverage) if coverage else None
        if blocking:
            status = "fail"
        elif matches:
            status = "pass"
        elif tested is True:
            status = "pass"
        else:
            status = "not_assessed"
        rows.append({
            "control_id":c.control_id,"framework":c.framework,"title":c.title,
            "description":c.description,"status":status,
            "evidence_count":len(matches),"blocking_count":len(blocking),
            "finding_ids":[str(f.get("finding_id")) for f in matches if f.get("finding_id")],
            "max_severity":c.max_severity,
        })
    failed=sum(r["status"]=="fail" for r in rows)
    passed=sum(r["status"]=="pass" for r in rows)
    assessed=passed+failed
    score=round(100*passed/max(1,assessed),1) if assessed else 0.0
    return {"framework":framework or "all","score":score,"passed":passed,"failed":failed,"controls":rows,"generated_at":datetime.now(timezone.utc).isoformat()}

def to_sarif(findings:Any, tool_name="MIRSAD", uri_base="") ->dict:
    fs=normalize_findings(findings)
    rules={}
    results=[]
    for f in fs:
        sev=str(f.get("severity","Info")).title()
        level={"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"note"}.get(sev,"note")
        rid=str(f.get("finding_id") or "finding")
        rules[rid]={
            "id":rid,
            "name":str(f.get("title") or rid)[:200],
            "shortDescription":{"text":str(f.get("title") or rid)[:200]},
            "fullDescription":{"text":str(f.get("description") or "")[:1000]},
            "help":{"text":str(f.get("remediation") or "Review and remediate the finding.")[:2000]},
            "properties":{"severity":sev,"confidence":f.get("confidence")}
        }
        asset=str(f.get("affected_asset") or "")
        loc={"physicalLocation":{"artifactLocation":{"uri":asset or uri_base or "target"}}}
        results.append({
            "ruleId":rid,"level":level,
            "message":{"text":str(f.get("description") or f.get("title") or "Security finding")[:4000]},
            "locations":[loc],
            "properties":{"severity":sev,"finding_id":rid,"source_module":f.get("source_module","")}
        })
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
            "runs":[{"tool":{"driver":{"name":tool_name,"rules":list(rules.values())}},
                     "results":results}]}

def ci_gate(findings:Any, policy:dict|None=None, coverage: dict[str, Any] | None = None)->dict:
    fs=normalize_findings(findings); policy=policy or {}
    thresholds={"Critical":int(policy.get("critical_fail",0)),"High":int(policy.get("high_fail",0)),
                "Medium":int(policy.get("medium_fail",0))}
    counts={s:sum(1 for f in fs if str(f.get("severity","Info")).title()==s) for s in ("Critical","High","Medium","Low","Info")}
    failures=[]
    for sev,limit in thresholds.items():
        if counts[sev]>limit: failures.append(f"{sev} findings: {counts[sev]} > {limit}")
    # A gate that passes because a capability was never exercised is not the same
    # claim as a gate that passes because that capability was tested and clean
    # (RULE 27: passing the gate is not the same as the target being secure). This
    # never changes pass/fail — it only makes the untested surface visible to
    # whoever consumes the gate result.
    untested_capabilities: list[str] = []
    capabilities = (coverage or {}).get("capabilities") if isinstance(coverage, dict) else None
    if isinstance(capabilities, dict):
        for name, entry in capabilities.items():
            status = str((entry or {}).get("status", "")).upper()
            if status in {"NOT_TESTED", "NOT_CONFIGURED", "DISABLED", "SKIPPED"}:
                untested_capabilities.append(name)
    return {"passed":not failures,"exit_code":0 if not failures else 1,"counts":counts,"failures":failures,
            "policy":thresholds,"sarif":to_sarif(fs),"untested_capabilities":sorted(untested_capabilities)}
