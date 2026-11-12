"""Compliance mapping, assessment and SARIF export.

Deterministic findings remain authoritative. Compliance is a control-mapping layer:
finding -> control evidence -> control status. AI is never used to decide pass/fail.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone

SEVERITY_ORDER={"Critical":4,"High":3,"Medium":2,"Low":1,"Info":0}

@dataclass(frozen=True)
class Control:
    control_id:str
    framework:str
    title:str
    description:str
    tags:tuple[str,...]=()
    max_severity:str="Low"

CONTROLS=[
    Control("ASVS-1.2.1","OWASP ASVS","Application identity and access control","Authentication and authorization controls are enforced.",("auth",),"High"),
    Control("ASVS-4.1.3","OWASP ASVS","Access control enforcement","Protected resources enforce authorization server-side.",("api","auth","authorization"),"High"),
    Control("ASVS-14.4.3","OWASP ASVS","HTTP security headers","Security headers are present and correctly configured.",("web","headers"),"Medium"),
    Control("API-2.1","OWASP API Security","Broken authentication","API endpoints require appropriate authentication.",("api","auth"),"High"),
    Control("API-5.1","OWASP API Security","Broken function level authorization","Authorization is enforced consistently for sensitive API functions.",("api","authorization"),"High"),
    Control("API-8.1","OWASP API Security","Security misconfiguration","API configuration does not expose unsafe defaults.",("api","configuration"),"Medium"),
    Control("NIST-ID.AM-1","NIST CSF","Asset inventory","Assets are inventoried and monitored.",("asset","network","dns"),"Medium"),
    Control("NIST-PR.AC-4","NIST CSF","Access permissions","Access permissions are managed and reviewed.",("auth","authorization"),"High"),
    Control("NIST-DE.CM-8","NIST CSF","Vulnerability monitoring","Systems are monitored for vulnerabilities and changes.",("scanner","asm","vulnerability"),"High"),
    Control("CIS-4.1","CIS Controls","Secure configuration","Secure configurations are established and maintained.",("configuration","headers"),"Medium"),
    Control("CIS-7.1","CIS Controls","Continuous vulnerability management","Vulnerabilities are continuously identified and managed.",("scanner","vulnerability","asm"),"High"),
    Control("CUSTOM-SCOPE-1","Custom","Target scope enforcement","Security testing is restricted to explicitly authorized targets.",("scope",),"High"),
]

def controls(framework: str|None=None)->list[Control]:
    return [c for c in CONTROLS if not framework or c.framework.lower()==framework.lower()]

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

def assess(findings:Any, framework:str|None=None)->dict:
    fs=normalize_findings(findings)
    cs=controls(framework)
    rows=[]
    for c in cs:
        matches=[f for f in fs if _matches(c,f)]
        blocking=[f for f in matches if SEVERITY_ORDER.get(str(f.get("severity","Info")).title(),0)>=SEVERITY_ORDER.get(c.max_severity,1)]
        status="pass" if not blocking else "fail"
        if matches and not blocking: status="pass_with_observations"
        rows.append({
            "control_id":c.control_id,"framework":c.framework,"title":c.title,
            "description":c.description,"status":status,
            "evidence_count":len(matches),"blocking_count":len(blocking),
            "finding_ids":[str(f.get("finding_id")) for f in matches if f.get("finding_id")],
            "max_severity":c.max_severity,
        })
    failed=sum(r["status"]=="fail" for r in rows)
    passed=sum(r["status"] in {"pass","pass_with_observations"} for r in rows)
    score=round(100*passed/max(1,len(rows)),1)
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

def ci_gate(findings:Any, policy:dict|None=None)->dict:
    fs=normalize_findings(findings); policy=policy or {}
    thresholds={"Critical":int(policy.get("critical_fail",0)),"High":int(policy.get("high_fail",0)),
                "Medium":int(policy.get("medium_fail",0))}
    counts={s:sum(1 for f in fs if str(f.get("severity","Info")).title()==s) for s in ("Critical","High","Medium","Low","Info")}
    failures=[]
    for sev,limit in thresholds.items():
        if counts[sev]>limit: failures.append(f"{sev} findings: {counts[sev]} > {limit}")
    return {"passed":not failures,"exit_code":0 if not failures else 1,"counts":counts,"failures":failures,
            "policy":thresholds,"sarif":to_sarif(fs)}
