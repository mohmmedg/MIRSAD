from __future__ import annotations
import hashlib
from app.integrations.defectdojo.models import Finding
def fingerprint(f) -> str:
    raw="|".join(str(x or "").strip().lower() for x in (f.source_module,f.rule_id,f.affected_asset,getattr(f,"parameter",None),f.title))
    return hashlib.sha256(raw.encode()).hexdigest()
def to_finding(f) -> Finding:
    cwe=(f.cwe or {}).get("id") if isinstance(f.cwe,dict) else None
    try: cwe=int(str(cwe).split("-")[-1]) if cwe else None
    except ValueError: cwe=None
    return Finding(title=f.title,severity=f.severity,description=f.description,unique_id_from_tool=fingerprint(f),references=f.references,cwe=cwe,cve=f.cve)
