from __future__ import annotations
import json
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.core.security import verify_api_key, require_analyst, require_viewer
from app.core.config import verify_target_in_scope
from app.core.auth_context import tenant_context
from app.core.assessment_lifecycle import list_status, update_status_async, sync_scan_findings, LifecycleVersionConflict
from app.core.scan_profiles import PROFILES
from app.core.architecture.history import history
from app.modules.correlator.correlator import finding_fingerprint

router=APIRouter(prefix='/assessment',tags=['assessment'])

class ReplayRequest(BaseModel):
    url:str
    method:str='GET'
    headers:dict[str,str]=Field(default_factory=dict)
    body:str|None=None
    timeout_seconds:int=10
    allow_mutation:bool=False

@router.get('/profiles',dependencies=[Depends(verify_api_key),Depends(require_viewer)])
async def profiles(): return {'profiles':PROFILES,'safe_modes':['safe','caution','destructive']}

@router.post('/replay',dependencies=[Depends(verify_api_key),Depends(require_analyst)])
async def replay(req:ReplayRequest):
    method=req.method.upper()
    if method not in {'GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'}: raise HTTPException(400,'Unsupported HTTP method')
    if method not in {'GET','HEAD','OPTIONS'} and not req.allow_mutation: raise HTTPException(400,'Mutation replay requires allow_mutation=true')
    host=urlparse(req.url).hostname
    if not host: raise HTTPException(400,'Invalid URL')
    verify_target_in_scope(host)
    headers={k:v for k,v in req.headers.items() if k.lower() not in {'authorization','proxy-authorization','cookie','set-cookie'}}
    try:
        async with httpx.AsyncClient(follow_redirects=False,timeout=max(1,min(req.timeout_seconds,30)),verify=True) as client:
            r=await client.request(method,req.url,headers=headers,content=req.body if req.body is not None else None)
        return {'status':'completed','request':{'method':method,'url':req.url,'headers':headers,'body':req.body if method in {'POST','PUT','PATCH'} else None},'response':{'status_code':r.status_code,'headers':dict(r.headers),'content_length':len(r.content),'elapsed_ms':round(r.elapsed.total_seconds()*1000,1),'body_preview':r.text[:4000]}}
    except Exception as exc: raise HTTPException(502,f'Replay failed: {str(exc)[:500]}') from exc

@router.get('/scans/{scan_id}/lifecycle',dependencies=[Depends(verify_api_key),Depends(require_viewer)])
async def lifecycle(scan_id:str):
    scan=await history.get(scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    await sync_scan_findings(scan)
    return {'scan_id':scan_id,'items':await list_status(scan_id)}

@router.patch('/scans/{scan_id}/findings/{finding_id}/lifecycle',dependencies=[Depends(verify_api_key),Depends(require_analyst)])
async def lifecycle_update(scan_id:str,finding_id:str,status:str,note:str='',base_version:int|None=None,idempotency_key:str|None=None):
    # *** إضافة (دعم Local-First): base_version/idempotency_key اختياريان
    # ومتوافقان للخلف تمامًا — أي استدعاء لا يمررهما (كل الاستدعاءات
    # الحالية بالواجهة عدا outbox.ts) يحصل على نفس السلوك القديم بالضبط. ***
    try:
        result=await update_status_async(scan_id,finding_id,status,note,base_version=base_version,idempotency_key=idempotency_key)
    except LifecycleVersionConflict as exc:
        # 409 حقيقي مع الحالة الحالية بالسيرفر — يستخدمها العميل لحل
        # التعارض محليًا (mergeByFieldLWW) بدون طلب GET إضافي.
        raise HTTPException(409,{
            'detail':'Finding lifecycle was modified by another session',
            'current_status':exc.current['status'],
            'current_note':exc.current['note'],
            'current_version':exc.current['version'],
            'current_updated_at':exc.current['updated_at'],
        }) from exc
    if result is None: raise HTTPException(404,'Finding lifecycle record not found')
    return result

@router.get('/scans/{scan_id}/surface',dependencies=[Depends(verify_api_key),Depends(require_viewer)])
async def surface(scan_id:str):
    scan=await history.get(scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    assets=[]
    for a in scan.assets:
        assets.append(a)
    return {'scan_id':scan_id,'target':scan.target,'assets':assets,'subdomains':scan.subdomains,'changes':[(a.get('surface_changes') or []) for a in assets if isinstance(a,dict)],'findings':len(scan.findings)}

# ---------------------------------------------------------------------------
# Attack Surface Intelligence Graph
# ---------------------------------------------------------------------------

def _graph_id(kind: str, value: object) -> str:
    import hashlib
    raw=f"{kind}:{value}".encode("utf-8", "ignore")
    return f"{kind}:{hashlib.sha1(raw, usedforsecurity=False).hexdigest()[:16]}"


def _graph_value(value: object) -> str:
    if value is None: return ""
    return str(value).strip()


def build_attack_surface_graph(scan):
    """Build a deterministic graph exclusively from the persisted scan snapshot."""
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def node(kind, value, label=None, details=None, parent=None):
        value=_graph_value(value)
        if not value: return None
        nid=_graph_id(kind, value)
        if nid not in nodes:
            nodes[nid]={"id":nid,"type":kind,"label":label or value,"value":value,"details":details or {},"severity":None}
        elif details:
            nodes[nid]["details"]={**nodes[nid].get("details",{}),**details}
        return nid

    def edge(source, target, relation, evidence=None):
        if not source or not target or source == target: return
        eid=_graph_id("edge", f"{source}|{target}|{relation}")
        if eid not in edges:
            edges[eid]={"id":eid,"source":source,"target":target,"relation":relation,"evidence":evidence or ""}

    target=_graph_value(scan.target)
    root=node("domain", target, details={"scan_id":scan.scan_id,"status":scan.status,"risk_score":scan.risk_score})

    dns=scan.dns or {}
    dns_id=node("dns", f"DNS:{target}", "DNS", dns)
    edge(root,dns_id,"resolved_by")
    for ip in (dns.get("addresses") or dns.get("ips") or []):
        ip_id=node("ip", ip, details={"source":"DNS snapshot"})
        edge(root,ip_id,"resolves_to",f"DNS resolution: {ip}")
        edge(dns_id,ip_id,"returns")
    records=dns.get("records") or dns.get("answers") or []
    if isinstance(records, dict): records=[records]
    for record in records:
        if isinstance(record, dict):
            rv=f"{record.get('type','record')}:{record.get('name') or target}:{record.get('value') or record.get('data') or ''}"
            rid=node("dns_record",rv, f"{record.get('type','DNS')} record", record)
        else:
            rid=node("dns_record",str(record), details={"source":"DNS snapshot"})
        edge(dns_id,rid,"contains_record")

    tls=scan.tls or {}
    if tls:
        cert=node("certificate", f"CERT:{target}", "SSL/TLS certificate", tls)
        edge(root,cert,"protected_by")
        for san in tls.get("subject_alt_names") or []:
            sid=node("subdomain", san, details={"source":"TLS certificate SAN"})
            edge(cert,sid,"names")
            edge(root,sid,"certificate_name")

    techs=list(scan.technologies or [])
    for tech in techs:
        tid=node("technology", tech)
        edge(root,tid,"uses")

    network=getattr(scan,"network_scan",None)
    for p in (getattr(network,"open_ports",[]) or []):
        port_value=f"{p.port}/{p.protocol}"
        pid=node("port", port_value, details={
            "port":p.port,"protocol":p.protocol,"state":str(p.state),"service_name":p.service_name,
            "product":p.product,"version":p.version,"extra_info":p.extra_info,"cpe":p.cpe,
            "scripts":[getattr(x,"model_dump",lambda: x)() for x in (p.scripts or [])]
        })
        edge(root,pid,"exposes")
        service_name=_graph_value(p.service_name or p.product)
        if service_name:
            sid=node("service", service_name, details={"port":p.port,"protocol":p.protocol,"product":p.product,"version":p.version})
            edge(pid,sid,"provides")
            edge(root,sid,"exposes_service")

    web=getattr(scan,"web_scan",None)
    for endpoint in (getattr(web,"endpoints",[]) or []):
        url=_graph_value(getattr(endpoint,"url",None))
        eid=node("endpoint", url, details=(endpoint.model_dump() if hasattr(endpoint,"model_dump") else {}))
        edge(root,eid,"contains_endpoint")

    api=getattr(scan,"api_scan",None)
    for endpoint in (getattr(api,"endpoints",[]) or []):
        url=_graph_value(getattr(endpoint,"url",None))
        eid=node("api_endpoint", url, details=(endpoint.model_dump() if hasattr(endpoint,"model_dump") else {}))
        edge(root,eid,"exposes_api")

    for sd in (scan.subdomains or []):
        host=_graph_value(sd.get("hostname") or sd.get("target")) if isinstance(sd,dict) else _graph_value(sd)
        sid=node("subdomain", host, details=sd if isinstance(sd,dict) else {"source":"scan"})
        edge(root,sid,"has_subdomain",(sd.get("evidence") if isinstance(sd,dict) else ""))

    for asset in (scan.assets or []):
        if not isinstance(asset,dict): continue
        atarget=_graph_value(asset.get("target") or asset.get("hostname"))
        if not atarget: continue
        aid=node("asset", atarget, details=asset)
        edge(root,aid,"asset")
        for ip in asset.get("ips") or []:
            iid=node("ip",ip); edge(aid,iid,"resolves_to")
        for port in asset.get("ports") or []:
            pid=node("port",str(port)); edge(aid,pid,"exposes")
        for svc in asset.get("services") or []:
            sid=node("service",str(svc)); edge(aid,sid,"provides")
        for tech in asset.get("technologies") or []:
            tid=node("technology",str(tech)); edge(aid,tid,"uses")
        for url in asset.get("endpoints") or asset.get("web_apps") or []:
            eid=node("endpoint",str(url)); edge(aid,eid,"contains_endpoint")

    for finding in (scan.findings or []):
        affected=_graph_value(getattr(finding,"affected_asset",None) or getattr(finding,"location",None) or "")
        fid=node("finding", getattr(finding,"finding_id",None), getattr(finding,"title",None), {
            "finding_id":finding.finding_id,"title":finding.title,"severity":finding.severity,
            "confidence":finding.confidence,"verification_status":finding.verification_status,
            "status":finding.status,"category":finding.category,"description":finding.description,
            "affected_asset":affected,"remediation":finding.remediation,"evidence":[e.model_dump() for e in (finding.evidence or [])],
            "references":finding.references,"cwe":finding.cwe,"owasp":finding.owasp,"mitre_attack":finding.mitre_attack,
            "cve_matches":finding.cve_matches,"discovery_method":finding.discovery_method,"discovery_command":finding.discovery_command,
        })
        nodes[fid]["severity"]=finding.severity
        if affected:
            aid=node("asset",affected)
            edge(fid,aid,"affects",f"{finding.title} → {affected}")
        else: edge(root,fid,"contains_finding")

    # Link duplicate node types to their strongest parent relationships where the
    # snapshot gives an unambiguous asset hostname. Keep the graph sparse and factual.
    for n in nodes.values():
        n["degree"]=0
    for e in edges.values():
        if e["source"] in nodes: nodes[e["source"]]["degree"]+=1
        if e["target"] in nodes: nodes[e["target"]]["degree"]+=1

    return {"scan_id":scan.scan_id,"target":scan.target,"generated_from":"persisted_scan_snapshot","nodes":list(nodes.values()),"edges":list(edges.values()),"counts":{"nodes":len(nodes),"edges":len(edges),"findings":len(scan.findings or []),"assets":len(scan.assets or []),"subdomains":len(scan.subdomains or [])}}


@router.get('/scans/{scan_id}/intelligence-graph', dependencies=[Depends(verify_api_key),Depends(require_viewer)])
async def intelligence_graph(scan_id:str, limit: int = 2000):
    scan=await history.get(scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    graph = build_attack_surface_graph(scan)
    limit = max(100, min(int(limit), 5000))
    if len(graph['nodes']) > limit:
        # Keep the response bounded; clients can request a larger window or use
        # export for offline analysis instead of receiving a 100k-node DOM payload.
        keep = {n['id'] for n in graph['nodes'][:limit]}
        graph['nodes'] = graph['nodes'][:limit]
        graph['edges'] = [e for e in graph['edges'] if e['source'] in keep and e['target'] in keep]
        graph['truncated'] = True
        graph['limit'] = limit
    else:
        graph['truncated'] = False
    return graph

@router.get('/scans/{scan_id}/intelligence-graph/export', dependencies=[Depends(verify_api_key),Depends(require_viewer)])
async def intelligence_graph_export(scan_id:str, format:str='json'):
    graph=await intelligence_graph(scan_id)
    fmt=format.lower()
    if fmt == 'json': return graph
    if fmt == 'csv':
        import csv, io
        out=io.StringIO(); w=csv.writer(out); w.writerow(['record','id','type','label','source','target','relation','severity','details'])
        for n in graph['nodes']: w.writerow(['node',n['id'],n['type'],n['label'],'','','',n.get('severity') or '',json.dumps(n.get('details') or {},ensure_ascii=False,default=str)])
        for e in graph['edges']: w.writerow(['edge',e['id'],'', '',e['source'],e['target'],e['relation'],'',e.get('evidence','')])
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(out.getvalue(),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename="mirsad-{scan_id}-graph.csv"'})
    if fmt in {'dot','graphviz'}:
        lines=['digraph MIRSAD {','  rankdir=LR;']
        for n in graph['nodes']:
            label=str(n['label']).replace('"','\\"'); lines.append(f'  "{n["id"]}" [label="{label}"];')
        for e in graph['edges']:
            rel=str(e['relation']).replace('"','\\"'); lines.append(f'  "{e["source"]}" -> "{e["target"]}" [label="{rel}"];')
        lines.append('}')
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse('\n'.join(lines),media_type='text/vnd.graphviz',headers={'Content-Disposition':f'attachment; filename="mirsad-{scan_id}-graph.dot"'})
    raise HTTPException(400,'format must be json, csv, or dot')
