import uuid
from urllib.parse import urlparse
from datetime import datetime, timezone
from app.modules.network_scan.scanner import NetworkScanner
from app.modules.web_scan.scanner import WebScanner
from app.modules.api_security.scanner import APISecurityScanner
from app.modules.normalizer.normalizer import normalize_bundle
from app.modules.correlator.correlator import correlate
from app.modules.risk_engine.engine import bundle_score
from app.modules.technology.fingerprint import fingerprint
from app.modules.technology.dns_tls import dns_snapshot, tls_snapshot
from app.modules.technology.js_analyzer import analyze_js
from app.modules.asset_inventory.inventory import inventory
from app.modules.auth_session.session import analyze_jwt
from app.schemas.platform import UnifiedScanResult, FullScanRequest, ScanComparison
from app.core.config import verify_target_in_scope
from app.core.architecture.history import history

class ScanManager:
    def __init__(self):
        self.network=NetworkScanner(); self.web=WebScanner(); self.api=APISecurityScanner()
    async def run(self, req: FullScanRequest, job=None) -> UnifiedScanResult:
        started=datetime.now(timezone.utc); scan_id=str(uuid.uuid4())
        # Defense-in-depth: full scans must pass scope/SSRF validation before any engine executes.
        target_for_guard = urlparse(req.target).hostname if "://" in req.target else req.target
        verify_target_in_scope(target_for_guard or req.target)
        network=web=api=None; warnings=[]
        if job:
            await job.checkpoint("network" if req.network else "web" if req.web else "api" if req.api else "finalize")
            if req.network: job.progress = 5; job.log("Network engine started")
        if req.network:
            network_target = urlparse(req.target).hostname if "://" in req.target else req.target
            network=await self.network.scan(network_target or req.target,req.network_profile,req.network_ports,req.network_timing)
            if job: job.progress = 25; job.log("Network engine completed")
        web_target = req.target if "://" in req.target else "https://" + req.target
        if req.web:
            if job: await job.checkpoint("web"); job.progress = max(job.progress, 30); job.log("Web engine started")
            web=await self.web.scan(web_target,req.web_profile,req.max_pages,req.max_depth,req.auth_header,req.cookie)
            if job: job.progress = 55; job.log("Web engine completed")
            api=getattr(web,"api_security",None) if req.api else None
        if req.api and api is None:
            if job: await job.checkpoint("api"); job.progress = max(job.progress, 60); job.log("API security engine started")
            api=await self.api.scan(target_url=web_target,spec_url=req.api_spec_url,auth_header=req.auth_header,cookie=req.cookie,enable_graphql_introspection=req.graphql_introspection,probe_write_methods=req.probe_write_methods)
            if job: job.progress = 75; job.log("API security engine completed")
        elif api is not None and req.auth_header:
            api.jwt_analysis=type(api.jwt_analysis)(**analyze_jwt(req.auth_header))
        if job: await job.checkpoint("normalizer"); job.progress = 82; job.log("Normalizer started")
        raw=normalize_bundle(network,web,api)
        findings=correlate(raw)
        ai_validation={}
        if req.run_gemini:
            if job: await job.checkpoint("ai_validation"); job.progress=91; job.log("Gemini validation started")
            try:
                from app.modules.ai_analysis.analyzer import AIAnalyzer, AIAnalyzerConfigError, AIAnalyzerResponseError
                ai_validation=await AIAnalyzer().validate_findings(findings, req.language)
            except (AIAnalyzerConfigError, AIAnalyzerResponseError) as exc:
                ai_validation={"status":"failed","reason":str(exc)}
                warnings.append("Gemini validation failed; rule-based findings remain authoritative.")
            if job: job.log("Gemini validation completed")
        if job: job.progress = 94; job.log("Correlation and risk calculation completed")
        tech=fingerprint(web,network,api)
        dns=dns_snapshot(web_target)
        tls=tls_snapshot(web_target)
        js=(web.javascript_intelligence if web else analyze_js([], []))
        ports=[f"{p.port}/{p.protocol}" for p in network.open_ports] if network else []
        endpoints=[e.url for e in web.endpoints] if web else []
        services=[f"{p.service_name or 'unknown'}:{p.port}/{p.protocol}" for p in (network.open_ports if network else [])]
        apis=[e.url for e in (api.endpoints if api else [])]
        web_apps=[web.target] if web else []
        finding_ids=[f.finding_id for f in findings]
        tls_expiry_days=None
        if tls.get("notAfter"):
            try:
                from email.utils import parsedate_to_datetime
                expiry=parsedate_to_datetime(tls["notAfter"])
                if expiry.tzinfo is None: expiry=expiry.replace(tzinfo=datetime.now(timezone.utc).tzinfo)
                tls_expiry_days=max(0,(expiry-datetime.now(timezone.utc)).days)
            except Exception: tls_expiry_days=None
        asset=inventory.upsert(req.target,tech,ports,endpoints,ips=(dns.get("addresses") or dns.get("ips") or []),services=services,web_apps=web_apps,apis=apis,finding_ids=finding_ids,snapshot={
            "ips": dns.get("addresses") or dns.get("ips") or [],
            "ports": ports, "services": services, "technologies": tech, "web_apps": web_apps,
            "apis": apis, "endpoints": endpoints,
            "dns_records": dns.get("records") or dns.get("addresses") or [],
            "tls_protocol": [tls.get("protocol")] if tls.get("protocol") else [],
            "tls_not_after": tls.get("notAfter"),
            "tls_expiry_days": tls_expiry_days
        })
        finished=datetime.now(timezone.utc)
        if job: await job.checkpoint("finalize"); job.progress = 96; job.log("Finalizing scan result")
        result=UnifiedScanResult(scan_id=scan_id,target=req.target,status="completed",started_at=started,finished_at=finished,network_scan=network,web_scan=web,api_scan=api,findings=findings,risk_score=bundle_score(findings),technologies=tech,assets=[asset],warnings=warnings,dns=dns,tls=tls,javascript_intelligence=js,ai_validation=ai_validation,coverage={"network": network.coverage if network else {}, "web": web.coverage if web else {}, "api": api.coverage if api else {}, "technologies": tech, "assets": 1})
        history.save(result)
        return result
    def compare(self, baseline: UnifiedScanResult, current: UnifiedScanResult):
        old={f.finding_id:f for f in baseline.findings}; new={f.finding_id:f for f in current.findings}
        return ScanComparison(baseline_id=baseline.scan_id,current_id=current.scan_id,new_findings=[f for k,f in new.items() if k not in old],fixed_finding_ids=[k for k in old if k not in new],unchanged_finding_ids=[k for k in old if k in new],severity_changes=[{"finding_id":k,"from":old[k].severity,"to":new[k].severity} for k in old.keys()&new.keys() if old[k].severity!=new[k].severity],score_delta=round(current.risk_score-baseline.risk_score,1))

manager=ScanManager()
