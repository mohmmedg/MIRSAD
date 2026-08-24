import hashlib
from sqlalchemy import select
from app.core.auth_context import tenant_context
from app.core.database import AssetRow, session_scope, utcnow
from app.core.policy_enforcement import scan_policy

SURFACE_FIELDS=("ips","ports","services","technologies","web_apps","apis","endpoints","dns_records","tls_protocol","tls_not_after","tls_expiry_days")

def _norm(values):
    return sorted({str(x) for x in (values or []) if x is not None})

def _diff(old, current):
    changes=[]
    for field in SURFACE_FIELDS:
        before=set(_norm(old.get(field,[])))
        after=set(_norm(current.get(field,[])))
        if field == "tls_not_after":
            before={old.get(field)} if old.get(field) else set(); after={current.get(field)} if current.get(field) else set()
        added=sorted(after-before); removed=sorted(before-after)
        if added or removed:
            changes.append({"field":field,"added":added,"removed":removed})
    return changes

class AssetInventory:
    def upsert(self,target,technologies=None,ports=None,endpoints=None,ips=None,services=None,web_apps=None,apis=None,finding_ids=None,snapshot=None):
        tid=tenant_context.get() or "legacy"; key=hashlib.sha256(target.strip().lower().encode()).hexdigest()[:16]
        with session_scope(tid) as db:
            row=db.get(AssetRow,key); now=utcnow(); old=(row.data or {}) if row else {}
            def merged(name, values): return sorted(set(old.get(name,[])) | {str(x) for x in (values or []) if x is not None})
            snap={k:_norm(v) if k != "tls_not_after" else (str(v) if v else None) for k,v in (snapshot or {}).items()}
            previous=old.get("surface_snapshot") or {}
            changes=[] if not previous else _diff(previous,snap)
            expiry=snap.get("tls_expiry_days")
            if expiry is not None and isinstance(expiry, list): expiry=int(expiry[0]) if expiry else None
            if expiry is not None and expiry <= 30:
                changes.append({"field":"tls_expiry_days","added":[str(expiry)],"removed":[],"warning":"TLS certificate expires within 30 days"})
            data={**old,"asset_id":key,"target":target,"ips":merged("ips",ips),"ports":merged("ports",ports),"services":merged("services",services),"technologies":merged("technologies",technologies),"web_apps":merged("web_apps",web_apps),"apis":merged("apis",apis),"endpoints":merged("endpoints",endpoints),"finding_ids":merged("finding_ids",finding_ids),"surface_snapshot":snap,"surface_changes":changes,"last_seen":now.isoformat()}
            if row is None:
                limit=int(scan_policy(tid)["max_assets"])
                count=db.scalar(select(__import__("sqlalchemy",fromlist=["func"]).func.count()).select_from(AssetRow).where(AssetRow.tenant_id==tid)) or 0
                if int(count) >= limit:
                    raise ValueError("Tenant asset inventory limit reached")
                data["first_seen"]=now.isoformat(); data["surface_baseline"]=True; db.add(AssetRow(asset_id=key,tenant_id=tid,target=target,data=data,first_seen=now,last_seen=now))
            else:
                row.target=target; row.data=data; row.last_seen=now
            return data
    def get(self,asset_id):
        tid=tenant_context.get() or "legacy"
        with session_scope(tid) as db:
            row=db.scalar(select(AssetRow).where(AssetRow.asset_id==asset_id, AssetRow.tenant_id==tid))
            return row.data if row else None
    def list(self):
        tid=tenant_context.get() or "legacy"
        with session_scope(tid) as db:
            rows=db.query(AssetRow).filter(AssetRow.tenant_id==tid).order_by(AssetRow.last_seen.desc()).limit(500).all()
            return [r.data for r in rows]
inventory=AssetInventory()
