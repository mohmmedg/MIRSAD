import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from app.schemas.platform import NormalizedFinding, FindingEvidence
from app.modules.threat_intel.enrichment import enrich_normalized_finding
from app.core.secret_redaction import redact
from urllib.parse import urlparse

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

def _severity(value: Any) -> str:
    v = str(value or "Info").title()
    return v if v in SEVERITY_ORDER else "Info"

def make_id(source: str, title: str, asset: str, evidence: str = "", *, method: str = "", parameter: str = "", rule: str = "", location: str = "") -> str:
    raw = "|".join([str(source).strip().lower(), str(asset).strip().lower(), str(method).strip().upper(), str(parameter).strip().lower(), str(rule or title).strip().lower(), str(location).strip().lower()])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _header_severity(header_name: str, web) -> tuple[str, dict[str, float], list[str]]:
    content_type = (getattr(web, "content_type", "") or "").lower()
    is_html = "html" in content_type
    has_auth = bool(getattr(web, "auth_present", False)) or any("auth" in str(x).lower() for x in getattr(web, "cookie_checks", []))
    endpoint_count = int(getattr(web, "endpoints_count", 0) or 0)
    if header_name == "Content-Security-Policy":
        sev = "Medium" if is_html and endpoint_count > 0 else "Low"
        ctx = {"exploitability": 0.5 if sev == "Medium" else 0.35, "exposure": 0.8 if is_html else 0.5, "asset_criticality": 0.75 if has_auth else 0.4}
    elif header_name == "Strict-Transport-Security":
        sev = "Medium" if has_auth else "Low"
        ctx = {"exploitability": 0.3, "exposure": 0.9 if has_auth else 0.6, "asset_criticality": 0.8 if has_auth else 0.4}
    elif header_name in {"X-Frame-Options", "Referrer-Policy", "Permissions-Policy"}:
        sev = "Medium" if is_html and has_auth else "Low"
        ctx = {"exploitability": 0.5 if sev == "Medium" else 0.35, "exposure": 0.75 if is_html else 0.4, "asset_criticality": 0.75 if has_auth else 0.4}
    else:
        sev = "Low"
        ctx = {"exploitability": 0.25, "exposure": 0.5, "asset_criticality": 0.4}
    return sev, ctx, ["web", "headers", "context-required"]

def verify_findings(findings: list[NormalizedFinding], *, verifier=None) -> dict[str, Any]:
    """Coordinate real verification; never promote a scanner observation by counting it as evidence."""
    counts={"VERIFIED":0,"DETECTED":0,"UNVERIFIED":0,"FALSE_POSITIVE":0,"NOT_APPLICABLE":0,"REJECTED":0}
    for f in findings:
        if f.verification_status == "VERIFIED" and not f.evidence:
            f.verification_status="UNVERIFIED"
        if verifier is not None and f.verification_status in {"DETECTED","UNVERIFIED"}:
            try:
                outcome=verifier(f)
                if outcome in {"VERIFIED","FALSE_POSITIVE","NOT_APPLICABLE","UNVERIFIED"}: f.verification_status=outcome
            except Exception as exc:
                f.verification_reason=f"verification failed: {type(exc).__name__}"
                f.verification_status="UNVERIFIED"
        if f.verification_status not in counts: f.verification_status="UNVERIFIED"
        counts[f.verification_status]+=1
    unresolved=counts["DETECTED"]+counts["UNVERIFIED"]
    return {"state":"COMPLETED" if findings and unresolved==0 else ("PARTIAL" if findings else "COMPLETED"),"findings_total":len(findings),"verified":counts["VERIFIED"],"detected":counts["DETECTED"],"unverified":counts["UNVERIFIED"],"false_positive":counts["FALSE_POSITIVE"],"not_applicable":counts["NOT_APPLICABLE"],"rejected":counts["REJECTED"],"all_findings_verified":bool(findings) and unresolved==0}



def _header_value_reobserved(actual: str, observed: str) -> bool:
    """True only when the *whole* header value seen now was also reported earlier.

    The previous check was a bare substring test, so a short value such as "no" or "1" matched
    almost any evidence text and produced false VERIFIED results. The value must now appear as a
    standalone token (not embedded in a longer word/value) and be at least 3 characters long.
    """
    value = str(actual or "").strip()
    if len(value) < 3:
        return False
    return re.search(r"(?<![\w./-])" + re.escape(value) + r"(?![\w./-])", str(observed or ""), re.I) is not None


async def verify_findings_live(findings: list[NormalizedFinding], *, scan_id: str | None = None, tenant_id: str | None = None, job_id: str | None = None) -> dict[str, Any]:
    """Perform bounded, read-only second-pass verification for findings where a safe
    deterministic replay is possible. Unknown/active-exploit candidates remain DETECTED.

    This deliberately does not replay destructive SQLi/RCE/default-credential payloads.
    Verification must produce fresh evidence; it never promotes a finding merely because
    a scanner emitted it.
    """
    import uuid
    import httpx
    from app.core.auth_context import tenant_context
    from datetime import datetime, timezone
    tid=tenant_id or tenant_context.get()
    utcnow=lambda: datetime.now(timezone.utc)
    counts={"VERIFIED":0,"DETECTED":0,"UNVERIFIED":0,"FALSE_POSITIVE":0,"NOT_APPLICABLE":0,"REJECTED":0}
    candidates=[]
    for f in findings:
        rule=str(f.rule_id or '').upper()
        if rule.startswith(('WEB-CORS-','WEB-HEADER-CONFIG-','WEB-SERVER-DISCLOSURE','WEB-COOKIE-')) and f.affected_asset:
            candidates.append(f)
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False, verify=getattr(__import__('app.core.config',fromlist=['settings']),'settings').WEB_SCAN_VERIFY_TLS) as client:
        for f in candidates:
            before=f.verification_status; method='GET-REPLAY-READONLY'; status='UNVERIFIED'; evidence={}; reason='No fresh verification evidence was obtained.'
            try:
                headers={}
                if f.rule_id.upper().startswith('WEB-CORS-'):
                    headers['Origin']='https://mirsad.invalid'
                response=await client.get(str(f.affected_asset),headers=headers)
                evidence={"http_status":response.status_code,"headers":{k:v[:500] for k,v in response.headers.items() if k.lower() in {'access-control-allow-origin','access-control-allow-credentials','server','set-cookie','content-security-policy','strict-transport-security','x-frame-options','referrer-policy','permissions-policy'}},"final_url":str(response.url)}
                rule=f.rule_id.upper()
                if rule.startswith('WEB-CORS-'):
                    acao=response.headers.get('access-control-allow-origin','')
                    acc=response.headers.get('access-control-allow-credentials','').lower()=='true'
                    if acao == 'https://mirsad.invalid' and acc:
                        status='VERIFIED'; reason='Second read-only request reproduced browser-readable cross-origin credentials policy.'
                    elif rule == 'WEB-CORS-CONFIG':
                        status='DETECTED'; reason='CORS was observed again, but the replay did not reproduce a credentialed cross-origin exposure.'
                    else:
                        status='UNVERIFIED'; reason='The previously reported CORS condition was not reproduced by the verification request.'
                elif rule.startswith('WEB-HEADER-CONFIG-'):
                    header=rule[len('WEB-HEADER-CONFIG-'):].replace('_','-')
                    actual=next((v for k,v in response.headers.items() if k.lower()==header.lower()),None)
                    observed=' '.join(str(e.evidence) for e in f.evidence)
                    if actual is None:
                        status='VERIFIED'; reason='Header is still absent on a fresh response.'
                    elif actual and _header_value_reobserved(actual, observed):
                        status='VERIFIED'; reason=f'Same weak header value re-observed: {actual!r}.'
                    else:
                        status='UNVERIFIED'; reason=f'Header replay returned {actual!r}, which does not reproduce the reported condition.'
                elif rule.startswith('WEB-COOKIE-'):
                    cookies=response.headers.get_list('set-cookie') if hasattr(response.headers,'get_list') else ([response.headers.get('set-cookie')] if response.headers.get('set-cookie') else [])
                    title_lower=str(f.title).lower()
                    matched=[]
                    for cookie in cookies:
                        if cookie and ('secure' in title_lower and '; secure' not in cookie.lower()): matched.append(cookie)
                        elif cookie and ('httponly' in title_lower and '; httponly' not in cookie.lower()): matched.append(cookie)
                        elif cookie and ('samesite' in title_lower and 'samesite=' not in cookie.lower()): matched.append(cookie)
                        elif cookie and 'samesite=none' in title_lower and 'samesite=none' in cookie.lower() and '; secure' not in cookie.lower(): matched.append(cookie)
                    status='VERIFIED' if matched else ('UNVERIFIED' if cookies else 'UNVERIFIED')
                    reason='The cookie attribute weakness was reproduced on a fresh Set-Cookie response.' if matched else 'The reported cookie attribute weakness was not reproduced by the verification response.'
                elif rule.startswith('WEB-SERVER-DISCLOSURE'):
                    status='VERIFIED' if response.headers.get('server') or response.headers.get('x-powered-by') else 'UNVERIFIED'
                    reason='Server technology disclosure was re-observed.' if status=='VERIFIED' else 'Server disclosure was not reproduced.'
                f.verification_status=status; f.verification_reason=reason; f.verification_method=method; f.verification_timestamp=utcnow().isoformat()
                if status=='VERIFIED': f.tags=list(dict.fromkeys(list(f.tags)+['verified-live']))
                elif status=='UNVERIFIED': f.tags=list(dict.fromkeys(list(f.tags)+['verification-failed']))
            except Exception as exc:
                f.verification_status='UNVERIFIED'; f.verification_reason=f'live verification failed: {type(exc).__name__}'; f.verification_method=method; f.verification_timestamp=utcnow().isoformat(); evidence={"error":type(exc).__name__}
                status='UNVERIFIED'
            if tid and scan_id:
                from app.core.database import VerificationEventRow, session_scope_sync
                with session_scope_sync(tenant_id=tid) as db:
                    db.add(VerificationEventRow(event_id='ve_'+uuid.uuid4().hex,tenant_id=tid,scan_id=scan_id,finding_id=f.finding_id,method=method,status_from=before,status_to=status,evidence=evidence,request_ref=str(f.affected_asset),response_ref=None,created_at=utcnow()))
    for f in findings:
        counts[f.verification_status if f.verification_status in counts else 'UNVERIFIED'] += 1
    unresolved=counts['DETECTED']+counts['UNVERIFIED']
    return {"state":"COMPLETED" if findings and unresolved==0 else ("PARTIAL" if findings else "COMPLETED"),"findings_total":len(findings),"verified":counts['VERIFIED'],"detected":counts['DETECTED'],"unverified":counts['UNVERIFIED'],"false_positive":counts['FALSE_POSITIVE'],"not_applicable":counts['NOT_APPLICABLE'],"rejected":counts['REJECTED'],"all_findings_verified":bool(findings) and unresolved==0,"live_verified":len(candidates)}

def normalize_bundle(network=None, web=None, api=None, scan_id: str | None = None) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    now = datetime.now(timezone.utc)
    if network:
        for p in network.open_ports:
            if str(getattr(p, "state", "open")).lower() not in {"open", "open|filtered"}:
                continue
            title = f"Open {p.port}/{p.protocol} service"
            evidence = f"{p.service_name or 'unknown'} {p.product or ''} {p.version or ''}".strip()
            tags = ["network", p.protocol]
            if p.service_name: tags.append(p.service_name.lower())
            out.append(NormalizedFinding(finding_id=make_id("network", title, f"{network.target}:{p.port}/{p.protocol}"), scan_id=scan_id, source_module="network", title=title, severity="Info", confidence=0.98, description="خدمة شبكية مكشوفة؛ الأهمية الأمنية تعتمد على الخدمة والإصدار ونتائج NSE.", evidence=[FindingEvidence(source="nmap", asset=f"{network.target}:{p.port}/{p.protocol}", evidence=evidence, confidence=0.98)], affected_asset=f"{network.target}:{p.port}/{p.protocol}", tags=tags, first_seen=now, last_seen=now, discovery_method="Nmap service/version detection", discovery_command=getattr(network, "raw_nmap_command", None), exploitability="Not established by port exposure alone; depends on service version, configuration, authentication and a verified weakness.", impact="The exposed service increases the reachable attack surface and may permit interaction with the service from the scanning position."))
            for s in p.scripts:
                text=s.output or ""
                low=text.lower()
                if any(x in low for x in ("vulnerable", "cve-", "vulners", "state: vulnerable")):
                    sev="High" if "critical" in low or "remote code" in low else "Medium"
                    title=f"NSE security indicator: {s.script_id}"
                    asset=f"{network.target}:{p.port}/{p.protocol}"
                    out.append(NormalizedFinding(finding_id=make_id("network",title,asset,text), scan_id=scan_id, title=title, severity=sev, confidence=0.8, description="أظهر سكربت Nmap NSE مؤشراً أمنياً يحتاج تحققاً.", evidence=[FindingEvidence(source="nmap-nse", asset=asset, evidence=text, confidence=0.8)], affected_asset=asset, tags=["nse","verification-needed"], references=[x for x in text.split() if x.upper().startswith("CVE-")], first_seen=now, last_seen=now, discovery_method="Nmap NSE security script", discovery_command=getattr(network, "raw_nmap_command", None), exploitability="Potentially exploitable depending on the NSE evidence, affected version and configuration; manual verification is required.", impact="The NSE evidence indicates a security-relevant condition on an exposed network service."))
    if web:
        # Security headers are retained as web telemetry/compliance data, but are
        # intentionally NOT normalized into Findings. Missing headers are hardening
        # observations, not standalone vulnerabilities, and would otherwise create
        # repetitive noise on every scan.
        # Passive observations remain low-impact and evidence-backed. A wildcard CORS
        # header alone is not a Medium finding; authenticated/sensitive browser-readable
        # exposure requires explicit verification.
        cors_verified = getattr(web, "cors_verification", {}) or {}
        for note in web.cors_findings:
            verified_risk = cors_verified.get("status") == "VERIFIED_RISK" and "Verified browser-readable" in note
            out.append(NormalizedFinding(
                finding_id=make_id("web-cors","CORS configuration",web.target,note),
                scan_id=scan_id, source_module="web", rule_id="WEB-CORS-VERIFIED" if verified_risk else "WEB-CORS-CONFIG", title="Verified CORS data exposure" if verified_risk else "CORS configuration observation",
                severity="High" if verified_risk and cors_verified.get("sensitive_response") else ("Medium" if verified_risk else "Info"), confidence=0.95 if verified_risk else 0.9, status="CONFIRMED" if verified_risk else "OPEN", verification_status="VERIFIED" if verified_risk else "DETECTED", verification_method="web-cors-browser-readability" if verified_risk else None, verification_timestamp=now.isoformat() if verified_risk else None, verification_reason="Fresh cross-origin replay reproduced credentialed browser-readable exposure." if verified_risk else None,
                category="cors", description="تم إثبات قراءة المتصفح للاستجابة عبر Origin خارجي مع السماح بالاعتمادات؛ لذلك تُقيّم الخطورة سياقياً." if verified_risk else "تم رصد إعداد CORS يحتاج سياقاً إضافياً؛ wildcard وحده لا يثبت أثراً أمنياً.",
                evidence=[FindingEvidence(source="web-cors-verification",asset=web.target,evidence=(note + " | " + str(cors_verified)),confidence=0.95)],
                affected_asset=web.target, risk_context={"exploitability": 0.85 if verified_risk and cors_verified.get("sensitive_response") else (0.55 if verified_risk else 0.1), "exposure": 0.95 if verified_risk else 0.4, "asset_criticality": 0.9 if verified_risk and cors_verified.get("sensitive_response") else 0.45}, tags=["web","cors"] + (["sensitive","authenticated","verified"] if verified_risk else ["context-required"]), first_seen=now,last_seen=now))
        # Contextual header findings are retained when the scanner observed an
        # explicitly weak/invalid/absent security-header state. Correlation and
        # fingerprinting deduplicate repeated observations across scans.
        for h in getattr(web, "security_headers", []) or []:
            analysis = str(getattr(h, "analysis", "") or "").upper()
            if getattr(h, "present", False) and analysis in {"VALID", "PRESENT", ""}:
                continue
            name = str(getattr(h, "header_name", "unknown"))
            value = str(getattr(h, "value", "") or "")
            sev, ctx, tags = _header_severity(name, web)
            out.append(NormalizedFinding(
                finding_id=make_id("web-header", name, web.target, value),
                scan_id=scan_id, source_module="web", rule_id=f"WEB-HEADER-CONFIG-{name.upper().replace('-', '_')}",
                title=f"Security header configuration: {name}", severity=sev, confidence=0.9, status="OPEN", verification_status="VERIFIED", verification_method="security-header-response-observation", verification_timestamp=now.isoformat(), verification_reason="The header state was observed in a live HTTP response.",
                category="security-headers", description=f"تم رصد قيمة ضعيفة صراحةً لترويسة {name}.",
                evidence=[FindingEvidence(source="web-security-header", asset=web.target, evidence=f"{name}: {value}", confidence=0.9)],
                affected_asset=web.target, remediation=f"راجع قيمة {name} واستخدم الإعداد الموصى به للبيئة التطبيقية.",
                risk_context=ctx, tags=tags+["verified"], first_seen=now,last_seen=now))
        for note in web.passive_findings:
            if "Server header" in note or "X-Powered-By" in note:
                out.append(NormalizedFinding(
                    finding_id=make_id("web-passive","Information disclosure",web.target,note),
                    scan_id=scan_id, source_module="web", rule_id="WEB-SERVER-DISCLOSURE", title="Server information disclosure",
                    severity="Info", confidence=0.98, status="OPEN", verification_status="DETECTED",
                    category="information-disclosure", description="ترويسة الاستجابة تكشف معلومات تقنية.",
                    evidence=[FindingEvidence(source="web-http",asset=web.target,evidence=note,confidence=0.98)],
                    affected_asset=web.target, tags=["web","information-disclosure"], first_seen=now,last_seen=now))
        for c in web.vulnerability_checks:
            if c.vulnerable:
                is_default_creds = c.check_name == "default_credentials"
                is_lfi = c.check_name == "local_file_inclusion"
                is_heuristic = is_default_creds or c.check_name in ("sqli_boolean_blind", "sqli_time_blind")
                # Behavioural SQLi checks (timing / boolean-diff) are never
                # reported above Medium: they are inference, not observation, and
                # load from concurrent engines can reproduce them (18.4s vs 0.1s).
                sev = "Critical" if is_lfi else ("High" if (("sqli" in c.check_name.lower() and c.check_name not in ("sqli_boolean_blind", "sqli_time_blind")) or is_default_creds) else "Medium")
                asset=c.url or web.target
                heuristic_titles = {
                    "default_credentials": "استجابة تسجيل دخول مغايرة عن بيانات اعتماد افتراضية معروفة — يحتاج تأكيداً يدوياً",
                    "sqli_boolean_blind": "مؤشر SQL Injection عمياء (boolean-based) — يحتاج تأكيداً يدوياً",
                    "sqli_time_blind": "مؤشر SQL Injection عمياء (time-based) — يحتاج تأكيداً يدوياً",
                }
                title = heuristic_titles.get(c.check_name, c.check_name)
                # These checks infer vulnerability from *behaviour* (response
                # timing, or content diverging from a baseline) rather than
                # directly observing a fact like a reflected payload or a DB
                # error string, so they're reported as DETECTED — flagged for
                # a human to confirm — rather than VERIFIED even when
                # c.vulnerable is True. False positives are inherent to
                # inference-based detection (network jitter for time-based,
                # dynamic page content for boolean-based).
                verification = "DETECTED" if is_heuristic else "VERIFIED"
                poc_text = ""
                if getattr(c, "poc_request", None):
                    poc_text = f"\n\n--- Proof of Concept ---\nRequest:\n{c.poc_request}\n\nResponse:\n{c.poc_response or ''}"
                out.append(NormalizedFinding(finding_id=make_id("web",c.check_name,asset,c.evidence or ""), scan_id=scan_id, source_module="web", rule_id=f"WEB-{c.check_name.upper()}", title=title, severity=sev,
                    confidence=0.4 if is_heuristic else (0.55 if c.confidence=="low" else 0.8), status="OPEN", verification_status=verification, description="اختبار الويب أعاد مؤشراً يحتاج تحققاً مستقلاً.", evidence=[FindingEvidence(source="web-active",asset=asset,evidence=(c.evidence or "")+poc_text,confidence=0.6)], affected_asset=asset, tags=["web","active","verification-needed"]+(["poc-attached"] if poc_text else []), first_seen=now,last_seen=now))
        for x in web.template_findings:
            if x.matched:
                # 2.2: a second independent request confirmed the same match
                # (x.verified is True) upgrades this from a single-observation
                # detection to a verified finding; a verified=False (repeat
                # request did NOT reproduce it) or None (verification itself
                # failed) keeps the original single-observation confidence
                # rather than silently claiming certainty it doesn't have.
                verification = "VERIFIED" if x.verified is True else "DETECTED"
                confidence = 0.95 if x.verified is True else (0.7 if x.verified is False else 0.85)
                evidence_note = x.evidence or "matched"
                if x.verified is False:
                    evidence_note += " (تحذير: لم يُعاد تأكيد المطابقة في طلب تحقق ثانٍ — قد يكون مؤشراً عابراً)"
                out.append(NormalizedFinding(finding_id=make_id("web-template",x.name,x.url,x.evidence or ""), scan_id=scan_id, source_module="web", rule_id=x.template_id, title=x.name, severity=_severity(x.severity_hint), confidence=confidence, status="OPEN", verification_status=verification, description=f"تطابق القالب {x.template_id or x.name} ({x.name}) مع الهدف: {x.url}", evidence=[FindingEvidence(source=x.template_id,asset=x.url,evidence=evidence_note,confidence=confidence)], affected_asset=x.url, remediation="راجع التعرض وأزل الملف أو المسار أو عطّل الوظيفة غير اللازمة.", tags=["template"]+(["verified"] if x.verified is True else []), first_seen=now,last_seen=now))
        # TLS protocol/cipher findings are only ever generated from a completed,
        # verified handshake at that exact protocol version — never inferred.
        tls = getattr(web, "tls_info", None)
        if tls and tls.enabled:
            for proto in tls.weak_protocols_enabled:
                out.append(NormalizedFinding(
                    finding_id=make_id("web-tls", f"Deprecated TLS protocol enabled: {proto}", web.target, proto),
                    scan_id=scan_id, source_module="web", rule_id="WEB-TLS-WEAK-PROTOCOL", title=f"Deprecated TLS protocol enabled: {proto}",
                    severity="Medium", confidence=0.9, status="OPEN", verification_status="VERIFIED", verification_method="direct-tls-handshake", verification_timestamp=now.isoformat(), verification_reason="The condition was observed during an actual TLS handshake.", category="tls",
                    description="تم التحقق فعلياً من قبول الخادم لمصافحة TLS كاملة مع بروتوكول قديم ومهجور أمنياً.",
                    evidence=[FindingEvidence(source="tls-protocol-probe", asset=web.target, evidence=f"{proto}: ENABLED (verified via direct pinned handshake)", confidence=0.9)],
                    affected_asset=web.target, remediation="عطّل TLS 1.0/1.1 من إعداد الخادم واقتصر على TLS 1.2/1.3.",
                    risk_context={"exploitability": 0.4, "exposure": 0.7, "asset_criticality": 0.5},
                    tags=["web", "tls", "verified"], first_seen=now, last_seen=now))
            if tls.weak_cipher:
                out.append(NormalizedFinding(
                    finding_id=make_id("web-tls", "Weak TLS cipher suite negotiated", web.target, tls.weak_cipher_detail or ""),
                    scan_id=scan_id, source_module="web", rule_id="WEB-TLS-WEAK-CIPHER", title="Weak TLS cipher suite negotiated",
                    severity="Medium", confidence=0.85, status="OPEN", verification_status="VERIFIED", verification_method="direct-tls-handshake", verification_timestamp=now.isoformat(), verification_reason="The condition was observed during an actual TLS handshake.", category="tls",
                    description="تفاوض TLS الفعلي مع الخادم أسفر عن مجموعة تشفير ضعيفة معروفة.",
                    evidence=[FindingEvidence(source="tls-cipher", asset=web.target, evidence=f"negotiated_cipher={tls.weak_cipher_detail}", confidence=0.85)],
                    affected_asset=web.target, remediation="عطّل مجموعات التشفير الضعيفة (RC4/3DES/NULL/EXPORT/anonymous) من إعداد الخادم.",
                    risk_context={"exploitability": 0.45, "exposure": 0.7, "asset_criticality": 0.5},
                    tags=["web", "tls", "verified"], first_seen=now, last_seen=now))
            if tls.certificate_valid is False:
                out.append(NormalizedFinding(
                    finding_id=make_id("web-tls", "Invalid or expired TLS certificate", web.target, tls.error or ""),
                    scan_id=scan_id, source_module="web", rule_id="WEB-TLS-INVALID-CERT", title="شهادة TLS غير صالحة أو منتهية",
                    severity="High", confidence=0.9, status="OPEN", verification_status="VERIFIED", verification_method="direct-tls-handshake", verification_timestamp=now.isoformat(), verification_reason="The condition was observed during an actual TLS handshake.", category="tls",
                    description="فشل التحقق من شهادة TLS الحالية أثناء مصافحة فعلية مع الخادم — إما منتهية الصلاحية أو غير موثوقة.",
                    evidence=[FindingEvidence(source="tls-cert-verify", asset=web.target, evidence=tls.error or "certificate_valid=False", confidence=0.9)],
                    affected_asset=web.target, remediation="جدّد شهادة TLS فوراً من جهة إصدار موثوقة، وفعّل التجديد التلقائي إن أمكن.",
                    risk_context={"exploitability": 0.6, "exposure": 0.85, "asset_criticality": 0.6},
                    tags=["web", "tls", "verified"], first_seen=now, last_seen=now))
        # Cookie findings are read directly from the raw Set-Cookie attributes actually
        # observed on the wire, so every issue here is a verified fact, not a guess.
        for c in getattr(web, "cookie_details", []) or []:
            name = c.get("name") or "unknown"
            kind = c.get("kind", "non-sensitive")
            samesite_val = str(c.get("samesite") or "").strip().lower()
            issues: list[tuple[str, str, str]] = []
            if not c.get("secure"):
                issues.append(("WEB-COOKIE-MISSING-SECURE", f"Cookie '{name}' missing Secure attribute", "Medium" if kind == "sensitive" else "Low"))
            if kind == "sensitive" and not c.get("httponly"):
                issues.append(("WEB-COOKIE-MISSING-HTTPONLY", f"Sensitive cookie '{name}' missing HttpOnly attribute", "Medium"))
            if kind == "sensitive" and not samesite_val:
                issues.append(("WEB-COOKIE-MISSING-SAMESITE", f"Sensitive cookie '{name}' missing SameSite attribute", "Medium"))
            elif samesite_val == "none" and not c.get("secure"):
                issues.append(("WEB-COOKIE-SAMESITE-NONE-INSECURE", f"Cookie '{name}' uses SameSite=None without Secure", "Medium"))
            for rule_id, title, sev in issues:
                out.append(NormalizedFinding(
                    finding_id=make_id("web-cookie", title, web.target, name), scan_id=scan_id, source_module="web",
                    rule_id=rule_id, title=title, severity=sev, confidence=0.9, status="OPEN", verification_status="VERIFIED", verification_method="set-cookie-wire-observation", verification_timestamp=now.isoformat(), verification_reason="The weakness was observed directly in the received Set-Cookie attributes.", category="cookie",
                    description="تم رصد هذه الخاصية فعلياً من ترويسة Set-Cookie المستلمة من الخادم.",
                    evidence=[FindingEvidence(source="set-cookie", asset=web.target, evidence=f"cookie={name}, secure={c.get('secure')}, httponly={c.get('httponly')}, samesite={c.get('samesite')}, kind={kind}", confidence=0.9)],
                    affected_asset=web.target, remediation="أضف الخصائص الأمنية المناسبة (Secure/HttpOnly/SameSite) على ملفات تعريف الارتباط الحساسة.",
                    risk_context={"exploitability": 0.4, "exposure": 0.55, "asset_criticality": 0.7 if kind == "sensitive" else 0.35},
                    tags=["web", "cookie", "verified"], first_seen=now, last_seen=now))
        # Cache-Control is only ever flagged when correlated with a concretely
        # observed sensitive cookie on the same response — a narrow, evidence-based
        # signal, not a blanket "missing header" claim (RULE 9/16: no auto-escalation
        # from a header's mere absence).
        has_sensitive_cookie = any(c.get("kind") == "sensitive" for c in getattr(web, "cookie_details", []) or [])
        if has_sensitive_cookie:
            cache_header = next((h for h in web.security_headers if h.header_name == "Cache-Control"), None)
            cc_value = (cache_header.value if cache_header and cache_header.present else "") or ""
            if "no-store" not in cc_value.lower():
                out.append(NormalizedFinding(
                    finding_id=make_id("web-cache", "Cacheable response containing a sensitive cookie", web.target, cc_value),
                    scan_id=scan_id, source_module="web", rule_id="WEB-CACHE-SENSITIVE-CACHEABLE", title="Cacheable response containing a sensitive cookie",
                    severity="Low", confidence=0.7, status="OPEN", verification_status="VERIFIED", verification_method="cache-control-response-observation", verification_timestamp=now.isoformat(), verification_reason="The response and sensitive cookie were observed together on the wire.", category="cache",
                    description="تم رصد كوكي حساس (جلسة/مصادقة) فعلياً ضمن استجابة لا تحتوي Cache-Control: no-store، ما قد يسمح بتخزينها مؤقتاً في ذاكرة تخزين مشتركة.",
                    evidence=[FindingEvidence(source="cache-control", asset=web.target, evidence=f"cache-control={cc_value or 'absent'}, sensitive_cookie_present=true", confidence=0.7)],
                    affected_asset=web.target, remediation="أضف Cache-Control: no-store, no-cache على أي استجابة تحمل بيانات جلسة أو مصادقة حساسة.",
                    risk_context={"exploitability": 0.3, "exposure": 0.5, "asset_criticality": 0.5},
                    tags=["web", "cache", "context-required"], first_seen=now, last_seen=now))
    if api:
        for m in api.template_matches:
            out.append(NormalizedFinding(finding_id=make_id("api-template",m.title,m.endpoint,m.evidence), scan_id=scan_id, source_module="api_security", rule_id=m.template_id, title=m.title, severity=_severity(m.severity), confidence=0.82, status="OPEN", verification_status="DETECTED", description="قالب API اكتشف مؤشراً يحتاج مراجعة.", evidence=[FindingEvidence(source=m.template_id,asset=m.endpoint,evidence=m.evidence,confidence=0.82)], affected_asset=m.endpoint, remediation=m.remediation, tags=["api","template"], first_seen=now,last_seen=now))
        for v in api.schema_validations:
            if v.valid is False:
                out.append(NormalizedFinding(finding_id=make_id("api-schema",f"API schema mismatch {v.method}",v.endpoint,";".join(v.errors)), scan_id=scan_id, source_module="api_security", rule_id="API-SCHEMA-MISMATCH", title=f"API schema mismatch: {v.method} {v.endpoint}", severity="Medium", confidence=0.9, status="OPEN", verification_status="VERIFIED", verification_method="openapi-schema-validation", verification_timestamp=now.isoformat(), verification_reason="The observed request/response failed the declared OpenAPI schema validation.", description="الاستجابة أو الطلب لا يتوافق مع المخطط المعلن.", evidence=[FindingEvidence(source="openapi-schema",asset=v.endpoint,evidence="; ".join(v.errors),confidence=0.9)], affected_asset=v.endpoint, remediation="حدّث التنفيذ أو مخطط OpenAPI ليكونا متطابقين.", tags=["api","openapi","schema"], first_seen=now,last_seen=now))
        # GraphQL introspection is a verified information-disclosure observation
        # (the schema was literally retrieved) — Low severity by default, consistent
        # with how server-banner/technology disclosure is treated elsewhere.
        gql = getattr(api, "graphql", None)
        if gql and gql.discovered and gql.introspection_attempted and gql.type_count > 0:
            gql_endpoint = gql.endpoint or api.target
            out.append(NormalizedFinding(
                finding_id=make_id("api-graphql", "GraphQL introspection enabled", gql_endpoint, str(gql.type_count)),
                scan_id=scan_id, source_module="api_security", rule_id="API-GRAPHQL-INTROSPECTION-ENABLED", title="GraphQL introspection enabled",
                severity="Low", confidence=0.95, status="OPEN", verification_status="VERIFIED", verification_method="graphql-introspection-request", verification_timestamp=now.isoformat(), verification_reason="A live introspection request returned a GraphQL schema.", category="information-disclosure",
                description="استعلام introspection القياسي أعاد مخطط GraphQL كاملاً (الأنواع والحقول)، ما يكشف بنية الواجهة الداخلية دون الحاجة لمصادقة.",
                evidence=[FindingEvidence(source="graphql-introspection", asset=gql_endpoint, evidence=f"types={gql.type_count}, fields={gql.field_count}, mutation_type={gql.mutation_type}", confidence=0.95)],
                affected_asset=gql_endpoint, remediation="عطّل introspection في بيئة الإنتاج أو قيّده بمصادقة/بيئة تطوير فقط.",
                tags=["api", "graphql", "information-disclosure"], first_seen=now, last_seen=now))
        # WebSocket findings: only ever generated from a completed HTTP-level Upgrade
        # handshake that was actually observed to be accepted — never from bare discovery.
        for ws in getattr(api, "websockets", []) or []:
            if not ws.handshake_attempted or not ws.handshake_accepted:
                continue
            out.append(NormalizedFinding(
                finding_id=make_id("api-ws", "WebSocket endpoint discovered", ws.url, str(ws.handshake_status)),
                scan_id=scan_id, source_module="api_security", rule_id="API-WEBSOCKET-DISCOVERED", title="WebSocket endpoint discovered",
                severity="Info", confidence=0.9, status="OPEN", verification_status="VERIFIED", verification_method="websocket-upgrade-handshake", verification_timestamp=now.isoformat(), verification_reason="A live HTTP Upgrade handshake was accepted.", category="attack-surface",
                description="تم التحقق من نقطة نهاية WebSocket فعلياً عبر مصافحة Upgrade آمنة على مستوى HTTP، دون تبادل أي بيانات عبر القناة.",
                evidence=[FindingEvidence(source="ws-handshake", asset=ws.url, evidence=f"handshake_status={ws.handshake_status}", confidence=0.9)],
                affected_asset=ws.url, tags=["api", "websocket", "attack-surface"], first_seen=now, last_seen=now))
            if ws.origin_test_attempted and ws.origin_reflected:
                out.append(NormalizedFinding(
                    finding_id=make_id("api-ws-origin", "WebSocket accepts handshake regardless of Origin", ws.url, str(ws.origin_test_status)),
                    scan_id=scan_id, source_module="api_security", rule_id="API-WEBSOCKET-ORIGIN-UNVALIDATED", title="WebSocket accepts handshake regardless of Origin",
                    severity="Medium", confidence=0.75, status="OPEN", verification_status="VERIFIED", verification_method="websocket-origin-probe", verification_timestamp=now.isoformat(), verification_reason="A live Origin probe was accepted by the WebSocket handshake.", category="websocket",
                    description="تم التحقق من قبول الخادم لمصافحة WebSocket رغم إرسال Origin غير متوقع؛ هذا مؤشر Cross-Site WebSocket Hijacking. الأثر الفعلي يعتمد على حساسية البيانات المتبادلة عبر القناة، وهو ما لم يُفحص هنا.",
                    evidence=[FindingEvidence(source="ws-origin-probe", asset=ws.url, evidence=f"origin_probe_status={ws.origin_test_status}, probe_origin=mirsad-cswsh-probe.invalid", confidence=0.75)],
                    affected_asset=ws.url, remediation="تحقق من ترويسة Origin على الخادم عند المصافحة وارفض الاتصالات من أصول غير موثوقة.",
                    risk_context={"exploitability": 0.4, "exposure": 0.6, "asset_criticality": 0.5},
                    tags=["api", "websocket", "context-required"], first_seen=now, last_seen=now))
        authz = getattr(api, "authorization_testing", {}) or getattr(web, "authorization_testing", {}) or {}
        for item in authz.get("findings", []) if isinstance(authz, dict) else []:
            evidence = f"authorized_status={item.get('authorized_status')}; unauthorized_status={item.get('unauthorized_status')}; url={item.get('url')}"
            out.append(NormalizedFinding(
                finding_id=make_id("api-authorization", "Authorization bypass candidate", str(item.get("url", api.target)), evidence),
                scan_id=scan_id, source_module="api_security", rule_id="API-AUTHZ-DIFFERENTIAL", title="Authorization bypass candidate",
                severity="High", confidence=0.8, status="OPEN", verification_status="VERIFIED", verification_method="authorization-differential-probe", verification_timestamp=now.isoformat(), verification_reason="Two explicitly supplied identities produced the observed differential response.", category="authorization",
                description="Two explicit test identities both received successful responses. This is a verified differential observation, but object-level authorization must be confirmed for the resource before calling it a vulnerability.",
                evidence=[FindingEvidence(source="api-authorization-test", asset=str(item.get("url", api.target)), evidence=evidence, confidence=0.8)],
                affected_asset=str(item.get("url", api.target)), tags=["api", "authorization", "verified", "requires-resource-confirmation"],
                risk_context={"exploitability": 0.75, "exposure": 0.9, "asset_criticality": 0.9}, first_seen=now, last_seen=now))
        for w in api.auth_findings:
            # Missing credentials is a coverage limitation, not a vulnerability.
            low = str(w).lower()
            if "no authentication material was supplied" in low or "cannot be fully distinguished" in low:
                continue
            severity = "Medium" if any(x in low for x in ("bypass", "unauthorized access", "authentication missing", "authorization")) else "Info"
            confidence = 0.7 if severity != "Info" else 0.95
            out.append(NormalizedFinding(
                finding_id=make_id("api-auth",w,api.target), scan_id=scan_id, source_module="api_security", rule_id="API-AUTH-BEHAVIOR", title=w,
                severity=severity, confidence=confidence, status="OPEN", verification_status="UNVERIFIED",
                description="مؤشر متعلق بالمصادقة أو التحكم بالوصول؛ يحتاج أدلة وصول قابلة للمقارنة قبل اعتباره ثغرة مؤكدة." if severity != "Info" else "قيد تغطية متعلق بالمصادقة؛ لم تُقدّم بيانات اعتماد كافية لإثبات تجاوز صلاحيات.",
                evidence=[FindingEvidence(source="api-auth",asset=api.target,evidence=w,confidence=confidence)],
                affected_asset=api.target, tags=["api","auth"] + (["verification-needed"] if severity != "Info" else ["coverage-limitation"]),
                first_seen=now,last_seen=now))
    # Authentication-protection inventory is intentionally separated from
    # vulnerability findings. "NOT_VERIFIED" means an active credential test was
    # not performed, not that the control is missing.
    auth_protection = getattr(web, "auth_protection", {}) or {}
    if isinstance(auth_protection, dict):
        for item in (auth_protection.get("findings") or []):
            check = str(item.get("check") or "authentication-protection")
            status = str(item.get("status") or "UNKNOWN")
            detail = str(item.get("detail") or "")
            sev = "Info"
            if status in {"NOT_OBSERVED", "NOT_VERIFIED"}:
                confidence = 0.98
                tags = ["auth", "coverage-status"]
            else:
                confidence = 0.9
                tags = ["auth", "observed-control"]
            out.append(NormalizedFinding(
                finding_id=make_id("auth-protection", check, web.target),
                scan_id=scan_id, source_module="web", rule_id=f"AUTH-PROTECTION-{check.upper().replace('-', '_')}",
                title=f"Authentication protection: {check}",
                severity=sev, confidence=confidence, status="OPEN", verification_status="OBSERVED",
                category="authentication", description=detail,
                evidence=[FindingEvidence(source="auth-protection", asset=web.target, evidence=f"{status}: {detail}", confidence=confidence)],
                affected_asset=web.target, tags=tags, first_seen=now, last_seen=now))
    # Optional Semgrep/Gitleaks/TruffleHog detector output is normalized
    # into the same canonical finding model. Secret detectors are correlated
    # by fingerprint before this stage, so one secret is not shown three times.
    # Web-only durable jobs can attach the external engines directly to
    # WebScanResult. Normalize them through the same canonical adapter used
    # by the full assessment manager.
    web_external = getattr(web, "external_scanners", {}) or {}
    if web_external:
        out.extend(normalize_external_scanners(web_external, scan_id=scan_id or getattr(web, "scan_id", ""), target=getattr(web, "target", "")))
    source_intel = getattr(web, "source_intelligence", {}) or {}
    detector_results = (source_intel.get("detectors") or {}) if isinstance(source_intel, dict) else {}
    for detector, payload in detector_results.items():
        if detector in {"correlated_secrets", "gitleaks", "trufflehog"} or not isinstance(payload, dict):
            continue
        for item in (payload.get("findings") or []):
            asset = str(item.get("matched_at") or web.target)
            title = str(item.get("name") or f"{detector} finding")
            evidence = str(item.get("evidence") or "REDACTED")
            sev = _severity(item.get("severity"))
            out.append(NormalizedFinding(
                finding_id=make_id(detector, title, asset, str(item.get("fingerprint") or item.get("rule_id") or evidence)),
                scan_id=scan_id, source_module=detector, rule_id=str(item.get("rule_id") or ""),
                title=title, severity=sev, confidence=0.75, status="OPEN",
                verification_status="DETECTED", category="source-analysis",
                description=str(item.get("description") or f"{detector} reported a source-level observation."),
                evidence=[FindingEvidence(source=detector, asset=asset, evidence=evidence, confidence=0.75)],
                affected_asset=asset, remediation="Review the source finding, validate the dataflow, and remediate the underlying issue.",
                tags=["source-analysis",detector,"verification-needed"], first_seen=now,last_seen=now,
            ))
    for item in (detector_results.get("correlated_secrets") or []):
        asset = str(item.get("matched_at") or web.target)
        detectors = list(dict.fromkeys(item.get("detectors") or []))
        detector_label = "+".join(detectors) if detectors else "secret-detectors"
        out.append(NormalizedFinding(
            finding_id=make_id("secret-correlation", "Correlated Secret Exposure", asset, str(item.get("fingerprint") or "")),
            scan_id=scan_id, source_module="secret-correlation", rule_id="SRC-SECRET-CORRELATED",
            title="Correlated Secret Exposure", severity="High", confidence=0.95,
            status="OPEN", verification_status="DETECTED", category="secret-exposure",
            description="Multiple independent secret detectors identified a source candidate.",
            evidence=[FindingEvidence(source=detector_label, asset=asset, evidence="REDACTED", confidence=0.95)],
            affected_asset=asset, remediation="Rotate/revoke the credential if valid, remove it from client-delivered source, and move secret material server-side.",
            tags=list(dict.fromkeys(["source-analysis","secret-exposure"] + detectors)), first_seen=now,last_seen=now,
        ))
    # Native Source Intelligence is enrichment-first: observations become
    # findings only when the contextual classifier emitted one. Endpoint
    # discoveries remain assets and are consumed by the API scanner.
    correlated_secret_assets = {
        str(x.get("matched_at") or web.target)
        for x in (detector_results.get("correlated_secrets") or [])
        if isinstance(x, dict)
    }
    for item in (source_intel.get("findings") or []):
        asset = str(item.get("asset") or web.target)
        if item.get("category") == "secret_exposure" and correlated_secret_assets:
            # The multi-detector correlated finding is the canonical secret issue.
            continue
        title = str(item.get("title") or "Source Intelligence observation")
        evidence = str(item.get("evidence_redacted") or "Source intelligence observation")
        sev = _severity(item.get("severity"))
        confidence = float(item.get("confidence") or 0.5)
        category = str(item.get("category") or "source-intelligence")
        tags = ["source-intelligence", category]
        for detector in item.get("detectors") or []:
            tags.append(str(detector)[:80])
        out.append(NormalizedFinding(
            finding_id=make_id("mirsad-source", title, asset, item.get("fingerprint") or evidence),
            scan_id=scan_id, source_module="mirsad-source", rule_id="SRC-" + re.sub(r"[^A-Z0-9_]+", "_", category.upper()).strip("_"),
            title=title, severity=sev, confidence=max(0.0,min(1.0,confidence)),
            status="OPEN", verification_status="DETECTED" if sev != "Info" else "UNVERIFIED",
            category=category, description=str(item.get("description") or "Native Source Intelligence correlated an observation from delivered application source."),
            evidence=[FindingEvidence(source=str(item.get("source") or "mirsad-source"), asset=asset, evidence=evidence, confidence=confidence)],
            affected_asset=asset, remediation=str(item.get("remediation") or ""),
            tags=list(dict.fromkeys(tags)), first_seen=now, last_seen=now,
        ))
    for f in out:
        if not f.rule_id:
            f.rule_id = "MIRSAD-" + f.source_module.upper() + "-OBSERVATION"
        observation_ids = []
        for e in f.evidence:
            e.evidence_id = e.evidence_id or hashlib.sha256((e.source + "|" + e.asset + "|" + e.evidence).encode()).hexdigest()
            oid = e.observation_id or "obs_" + hashlib.sha256((e.source + "|" + e.asset + "|" + e.evidence).encode()).hexdigest()[:24]
            e.observation_id = oid
            observation_ids.append(oid)
        f.observation_ids = list(dict.fromkeys(observation_ids))
        f.observation_count = len(f.observation_ids)
        f.evidence_count = len(f.evidence)
        enrich_normalized_finding(f)
    return out


def normalize_external_scanners(external: dict[str, Any], *, scan_id: str, target: str) -> list[NormalizedFinding]:
    """Single canonical adapter for external scanners with provenance."""
    out=[]; now=datetime.now(timezone.utc)
    severity_map={"Informational":"Info","Information":"Info","Low":"Low","Medium":"Medium","High":"High","Critical":"Critical"}
    for engine,payload in (external or {}).items():
        if not isinstance(payload,dict): continue
        status=str(payload.get("status") or "").upper()
        if status not in {"COMPLETED","PARTIAL","FAILED"}: continue
        execution_id=payload.get("execution_id")
        engine_result_id=payload.get("engine_result_id")
        for idx,item in enumerate(payload.get("findings") or []):
            title=str(item.get("name") or f"{engine} finding")
            asset=str(item.get("matched_at") or item.get("url") or target)
            method=str(item.get("method") or "")
            parameter=str(item.get("param") or item.get("parameter") or "")
            rule=str(item.get("template_id") or item.get("plugin_id") or item.get("rule_id") or "")
            if not rule:
                # sqlmap/ffuf items carry no native rule id; give them a stable one
                # so correlation, verification and exports stay deterministic.
                rule = f"{engine.upper()}-" + re.sub(r"[^A-Za-z0-9]+","-",str(item.get("type") or title)).strip("-").upper()[:60]
            loc=str(item.get("raw_locator") or f"index:{idx}")
            sev_raw=str(item.get("severity") or item.get("risk") or "Info")
            sev=severity_map.get(sev_raw.title(), "Info")
            raw_evidence=" | ".join(str(item.get(k)) for k in ("template_id","plugin_id","matched_at","url","param","parameter","payload","evidence","description") if item.get(k) is not None)
            classification=item.get("classification") or {}
            cwe=item.get("cwe") or classification.get("cwe-id") or classification.get("cwe")
            if isinstance(cwe,(list,tuple)): cwe=next((c for c in cwe if c),None)
            if cwe is not None:
                cwe=str(cwe).strip().upper()
                if cwe.isdigit(): cwe=f"CWE-{cwe}"
                if cwe in {"","CWE-0","CWE--1","NONE","NULL"}: cwe=None
            cve=item.get("cve") or classification.get("cve-id") or classification.get("cve")
            if isinstance(cve,(list,tuple)): cve=", ".join(str(c) for c in cve if c) or None
            cvss=item.get("cvss") or classification.get("cvss-score")
            epss=item.get("epss") or classification.get("epss")
            kev=item.get("kev")
            try: cvss=float(cvss) if cvss is not None else None
            except (TypeError,ValueError): cvss=None
            try: epss=float(epss) if epss is not None else None
            except (TypeError,ValueError): epss=None
            scanner_conf=item.get("confidence",payload.get("confidence",0.75))
            try: scanner_conf=float(scanner_conf)/100 if float(scanner_conf)>1 else float(scanner_conf)
            except (TypeError,ValueError): scanner_conf=0.75
            finding=NormalizedFinding(finding_id=make_id(engine,title,asset,method=method,parameter=parameter,rule=rule,location=loc),scan_id=scan_id,source_module=engine,rule_id=rule,title=title,severity=sev,confidence=scanner_conf,scanner_confidence=scanner_conf,tool_version=item.get("tool_version") or payload.get("version"),status="OPEN",verification_status="DETECTED",category=(str(item.get("category")) if item.get("category") else ("content-discovery" if engine=="ffuf" else ("tls-configuration" if engine=="testssl" else "external-dast"))),parameter=parameter or None,method=method or None,request=item.get("request"),response=item.get("response"),payload=item.get("payload"),location=loc,description=str(item.get("description") or f"{engine} reported a security-relevant observation."),evidence=[FindingEvidence(source=engine,asset=asset,evidence=raw_evidence or "external engine match",confidence=scanner_conf,reference=str(item.get("reference") or "") or None)],affected_asset=asset,remediation=str(item.get("solution") or "Review and independently verify the reported condition."),references=(item.get("reference") if isinstance(item.get("reference"),list) else ([str(item.get("reference"))] if item.get("reference") else [])),tags=["external-dast",engine,"verification-needed"]+( ["content-discovery"] if engine=="ffuf" else []),first_seen=now,last_seen=now,execution_id=execution_id,engine_result_id=engine_result_id,raw_artifact_id=item.get("raw_artifact_id") or payload.get("raw_artifact_id"),raw_locator=loc,raw_artifact_sha256=item.get("raw_artifact_sha256") or payload.get("raw_artifact_sha256"),verification_replay=item.get("verification_replay"),security_impact=item.get("security_impact"),independent_verification=item.get("independent_verification"),cve=str(cve) if cve else None,cvss=cvss,epss=epss,kev=bool(kev) if kev is not None else None,cwe={"id":str(cwe),"name":""} if cwe else None)
            out.append(finding)
    return out
