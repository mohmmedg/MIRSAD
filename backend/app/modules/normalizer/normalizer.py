import hashlib
from datetime import datetime, timezone
from typing import Any
from app.schemas.platform import NormalizedFinding, FindingEvidence

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

def _severity(value: Any) -> str:
    v = str(value or "Info").title()
    return v if v in SEVERITY_ORDER else "Info"

def make_id(source: str, title: str, asset: str, evidence: str = "") -> str:
    raw = f"{source}|{title.strip().lower()}|{asset.strip().lower()}|{evidence[:300]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]

def normalize_bundle(network=None, web=None, api=None) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    now = datetime.now(timezone.utc)
    if network:
        for p in network.open_ports:
            title = f"Open {p.port}/{p.protocol} service"
            evidence = f"{p.service_name or 'unknown'} {p.product or ''} {p.version or ''}".strip()
            tags = ["network", p.protocol]
            if p.service_name: tags.append(p.service_name.lower())
            out.append(NormalizedFinding(finding_id=make_id("network", title, f"{network.target}:{p.port}/{p.protocol}"), source_module="network", title=title, severity="Info", confidence=0.98, description="خدمة شبكية مكشوفة؛ الأهمية الأمنية تعتمد على الخدمة والإصدار ونتائج NSE.", evidence=[FindingEvidence(source="nmap", asset=f"{network.target}:{p.port}/{p.protocol}", evidence=evidence, confidence=0.98)], affected_asset=f"{network.target}:{p.port}/{p.protocol}", tags=tags, first_seen=now, last_seen=now))
            for s in p.scripts:
                text=s.output or ""
                low=text.lower()
                if any(x in low for x in ("vulnerable", "cve-", "vulners", "state: vulnerable")):
                    sev="High" if "critical" in low or "remote code" in low else "Medium"
                    title=f"NSE security indicator: {s.script_id}"
                    asset=f"{network.target}:{p.port}/{p.protocol}"
                    out.append(NormalizedFinding(finding_id=make_id("network",title,asset,text), source_module="network", title=title, severity=sev, confidence=0.8, description="أظهر سكربت Nmap NSE مؤشراً أمنياً يحتاج تحققاً.", evidence=[FindingEvidence(source="nmap-nse", asset=asset, evidence=text[:3000], confidence=0.8)], affected_asset=asset, tags=["nse","verification-needed"], references=[x for x in text.split() if x.upper().startswith("CVE-")][:10], first_seen=now, last_seen=now))
    if web:
        for h in web.security_headers:
            if not h.present:
                sev="Medium" if h.header_name in {"Content-Security-Policy","Strict-Transport-Security"} else "Low"
                asset=web.target
                title=f"Missing security header: {h.header_name}"
                out.append(NormalizedFinding(finding_id=make_id("web",title,asset), source_module="web", title=title, severity=sev, confidence=0.96, description=f"رأس HTTP الأمني {h.header_name} غير موجود في الاستجابة.", evidence=[FindingEvidence(source="web-http",asset=asset,evidence=f"Header {h.header_name}: missing",confidence=0.96)], affected_asset=asset, tags=["web","headers"], first_seen=now,last_seen=now))
        for c in web.vulnerability_checks:
            if c.vulnerable:
                sev="High" if "sqli" in c.check_name.lower() else "Medium"
                asset=c.url or web.target
                out.append(NormalizedFinding(finding_id=make_id("web",c.check_name,asset,c.evidence or ""), source_module="web", title=c.check_name, severity=sev, confidence=0.55 if c.confidence=="low" else 0.8, description="اختبار الويب أعاد مؤشراً يحتاج تحققاً مستقلاً.", evidence=[FindingEvidence(source="web-active",asset=asset,evidence=(c.evidence or "")[:2000],confidence=0.6)], affected_asset=asset, tags=["web","active","verification-needed"], first_seen=now,last_seen=now))
        for x in web.template_findings:
            if x.matched:
                out.append(NormalizedFinding(finding_id=make_id("web-template",x.name,x.url,x.evidence or ""), source_module="web", title=x.name, severity=_severity(x.severity_hint), confidence=0.85, description="قالب فحص أمني تطابق مع الهدف.", evidence=[FindingEvidence(source=x.template_id,asset=x.url,evidence=x.evidence or "matched",confidence=0.85)], affected_asset=x.url, remediation="راجع التعرض وأزل الملف أو المسار أو عطّل الوظيفة غير اللازمة.", tags=["template"], first_seen=now,last_seen=now))
    if api:
        for m in api.template_matches:
            out.append(NormalizedFinding(finding_id=make_id("api-template",m.title,m.endpoint,m.evidence), source_module="api_security", title=m.title, severity=_severity(m.severity), confidence=0.82, description="قالب API اكتشف مؤشراً يحتاج مراجعة.", evidence=[FindingEvidence(source=m.template_id,asset=m.endpoint,evidence=m.evidence,confidence=0.82)], affected_asset=m.endpoint, remediation=m.remediation, tags=["api","template"], first_seen=now,last_seen=now))
        for v in api.schema_validations:
            if v.valid is False:
                out.append(NormalizedFinding(finding_id=make_id("api-schema",f"API schema mismatch {v.method}",v.endpoint,";".join(v.errors)), source_module="api_security", title=f"API schema mismatch: {v.method} {v.endpoint}", severity="Medium", confidence=0.9, description="الاستجابة أو الطلب لا يتوافق مع المخطط المعلن.", evidence=[FindingEvidence(source="openapi-schema",asset=v.endpoint,evidence="; ".join(v.errors)[:2500],confidence=0.9)], affected_asset=v.endpoint, remediation="حدّث التنفيذ أو مخطط OpenAPI ليكونا متطابقين.", tags=["api","openapi","schema"], first_seen=now,last_seen=now))
        for w in api.auth_findings:
            # Missing credentials is a coverage limitation, not a vulnerability.
            low = str(w).lower()
            if "no authentication material was supplied" in low or "cannot be fully distinguished" in low:
                continue
            severity = "Medium" if any(x in low for x in ("bypass", "unauthorized access", "authentication missing", "authorization")) else "Info"
            confidence = 0.7 if severity != "Info" else 0.95
            out.append(NormalizedFinding(
                finding_id=make_id("api-auth",w,api.target), source_module="api_security", title=w,
                severity=severity, confidence=confidence,
                description="مؤشر متعلق بالمصادقة أو التحكم بالوصول؛ يحتاج أدلة وصول قابلة للمقارنة قبل اعتباره ثغرة مؤكدة." if severity != "Info" else "قيد تغطية متعلق بالمصادقة؛ لم تُقدّم بيانات اعتماد كافية لإثبات تجاوز صلاحيات.",
                evidence=[FindingEvidence(source="api-auth",asset=api.target,evidence=w,confidence=confidence)],
                affected_asset=api.target, tags=["api","auth"] + (["verification-needed"] if severity != "Info" else ["coverage-limitation"]),
                first_seen=now,last_seen=now))
    return out
