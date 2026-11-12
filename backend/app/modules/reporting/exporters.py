import csv, glob, html, io, re
from app.schemas.platform import UnifiedScanResult
from app.core.secret_redaction import redact

_ARABIC_RE = re.compile(r"[\u0600-\u06FF]")

# Candidate Arabic-capable font files across common Linux/Windows/macOS
# locations, plus a couple of filename globs for whichever Noto/Amiri
# package happens to be installed. DejaVu Sans/Helvetica (the previous
# fallback) contain no Arabic glyphs at all, which is why Arabic
# recommendations were rendering as unreadable boxes.
_ARABIC_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/noto/NotoNaskhArabic-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoNaskhArabic-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansArabic-Regular.ttf",
    "/usr/share/fonts/truetype/kacst/KacstOne.ttf",
    "/usr/share/fonts/truetype/amiri/Amiri-Regular.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "C:/Windows/Fonts/tahoma.ttf",
    "C:/Windows/Fonts/arial.ttf",
]
_ARABIC_FONT_GLOBS = [
    "/usr/share/fonts/**/*Arabic*.ttf",
    "/usr/share/fonts/**/*Amiri*.ttf",
    "/usr/share/fonts/**/*arabic*.ttf",
]

def _find_arabic_font() -> str | None:
    for path in _ARABIC_FONT_CANDIDATES:
        import os
        if os.path.exists(path):
            return path
    for pattern in _ARABIC_FONT_GLOBS:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return matches[0]
    return None

def _shape_arabic(text: str) -> str:
    """Reshape + apply bidi ordering to Arabic text so it renders as joined,
    right-to-left script instead of disconnected/reversed glyphs. Falls back
    to the original text if the optional shaping libraries aren't installed,
    or if the text has no Arabic characters at all (cheap no-op)."""
    if not text or not _ARABIC_RE.search(text):
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except ImportError:
        return text

def _safe(scan: UnifiedScanResult) -> UnifiedScanResult:
    return UnifiedScanResult.model_validate(redact(scan.model_dump(mode="json")))

def _surface(scan):
    assets = scan.assets[0] if scan.assets and isinstance(scan.assets[0], dict) else {}
    endpoints = []
    web = scan.web_scan
    if web and hasattr(web, "endpoints"):
        for e in web.endpoints:
            url = getattr(e, "url", "")
            endpoints.append({"url": url, "methods": list(getattr(e, "methods", []) or []), "findings": [f.finding_id for f in scan.findings if (f.affected_asset or "") == url]})
    return {"domain": scan.normalized_target or scan.target, "ips": assets.get("ips", []), "services": assets.get("services", []), "technologies": scan.technologies or assets.get("technologies", []), "endpoints": endpoints, "findings": [f.finding_id for f in scan.findings]}

def _verification_counts(scan):
    states={"VERIFIED":0,"DETECTED":0,"UNVERIFIED":0,"FALSE_POSITIVE":0,"NOT_APPLICABLE":0,"REJECTED":0}
    severities={k:0 for k in ("Critical","High","Medium","Low","Info")}
    for f in scan.findings:
        states[f.verification_status if f.verification_status in states else "UNVERIFIED"] += 1
        if f.severity in severities: severities[f.severity]+=1
    return states,severities

def to_json(scan: UnifiedScanResult, audience="technical"):
    safe=_safe(scan); states,severities=_verification_counts(safe)
    if audience in ("managerial", "non_technical"):
        # Do not expose internal IDs, fingerprints, asset inventories, raw evidence,
        # engine metadata, or execution/artifact references in managerial exports.
        return {
            "target": safe.target,
            "status": safe.status,
            "risk_score": safe.risk_score,
            "coverage": {"percentage": safe.coverage.percentage},
            "verification_summary": {"severity_counts": {k: sum(1 for f in safe.findings if f.confirmation_state == "CONFIRMED" and f.severity == k) for k in severities}, "total": len(safe.findings),
                                     "confirmed": sum(f.confirmation_state == "CONFIRMED" for f in safe.findings),
                                     "candidates": sum(f.confirmation_state != "CONFIRMED" for f in safe.findings)},
            "findings": [
                {"title": f.title, "severity": f.severity,
                 "remediation": f.remediation or "Review and remediate."}
                for f in safe.findings if f.confirmation_state == "CONFIRMED"
            ],
        }
    data=safe.model_dump(mode="json")
    data["attack_surface"]=_surface(safe)
    data["verification_summary"]={"counts":states,"severity_counts":severities,"total":len(safe.findings),
                                  "confirmed":sum(f.confirmation_state == "CONFIRMED" for f in safe.findings),
                                  "candidates":sum(f.confirmation_state != "CONFIRMED" for f in safe.findings)}
    return data

def _csv_cell(value):
    """Neutralize spreadsheet formula injection (=, +, -, @, tab, CR) in text that originates from scanned targets."""
    if isinstance(value, str) and value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


class _SafeCsvWriter:
    def __init__(self, writer): self._w = writer
    def writerow(self, row): return self._w.writerow([_csv_cell(v) for v in row])


def to_csv(scan: UnifiedScanResult, audience="technical") -> str:
    scan=_safe(scan); out=io.StringIO(); w=_SafeCsvWriter(csv.writer(out))
    if audience in ("managerial", "non_technical"):
        w.writerow(["title", "severity", "recommended_action"])
        for f in scan.findings:
            if f.confirmation_state == "CONFIRMED":
                w.writerow([f.title, f.severity, f.remediation or "Review and remediate."])
        return out.getvalue()
    w.writerow(["finding_id","fingerprint","scan_id","rule_id","title","severity","confidence","scanner_confidence","ai_confidence","status","verification_status","confirmation_state","assessment_state","confirmation_reason","asset","endpoint","parameter","category","cve","cwe","cvss","epss","kev","execution_id","engine_result_id","raw_artifact_id","raw_locator","duplicate_count","source_engines","evidence","remediation","references"])
    for f in scan.findings:
        w.writerow([f.finding_id,f.fingerprint,scan.scan_id,f.rule_id,f.title,f.severity,f.confidence,f.scanner_confidence,f.ai_confidence,f.status,f.verification_status,f.confirmation_state,f.assessment_state,f.confirmation_reason or "",f.affected_asset or "",getattr(f,"endpoint_id","") or f.affected_asset or "",f.parameter or "",f.category,f.cve or "",(f.cwe or {}).get("id","") if f.cwe else "",f.cvss if f.cvss is not None else "",f.epss if f.epss is not None else "",f.kev if f.kev is not None else "",f.execution_id or "",f.engine_result_id or "",f.raw_artifact_id or "",f.raw_locator or "",f.duplicate_count,", ".join(getattr(f,"source_engines",[]) or [f.source_module])," | ".join(e.evidence for e in f.evidence),f.remediation," | ".join(f.references)])
    return out.getvalue()

def to_html(scan: UnifiedScanResult, language="ar", audience="technical"):
    is_technical = audience not in ("managerial", "non_technical")
    scan = _safe(scan)
    title="Security Assessment" if language=="en" else "التقييم الأمني"
    rows=[]
    headers = ["Signal","Finding","Confirmation","Asset","Evidence","Risk","Confidence"] if is_technical else ["Severity","Finding","Recommended action"]
    for f in scan.findings:
        if is_technical:
            ev="<br>".join(html.escape(e.evidence[:1200]) for e in f.evidence[:3])
            rows.append(f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.confirmation_state)}</td><td>{html.escape(f.affected_asset or '')}</td><td>{ev or '—'}</td><td>{f.risk.score}</td><td>{f.confidence:.0%}</td></tr>")
        elif f.confirmation_state == "CONFIRMED":
            rows.append(f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.remediation or 'Review and remediate.')}</td></tr>")
    return f"""<!doctype html><html lang="{language}"><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:system-ui;margin:2rem;color:#16211e}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd7d3;padding:.5rem;text-align:left;vertical-align:top}}.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem}}@media print{{body{{margin:.5rem}}}}</style>
<h1>{html.escape(title)} — {html.escape(scan.target)}</h1><div class="meta"><p>Scan ID: <b>{html.escape(scan.scan_id)}</b></p><p>Risk: <b>{scan.risk_score}/100</b></p><p>Coverage: <b>{scan.coverage.percentage:.1f}%</b></p><p>Audience: <b>{html.escape(audience)}</b></p></div>
<p>Confirmed: {sum(f.confirmation_state == 'CONFIRMED' for f in scan.findings)} · Candidates: {sum(f.confirmation_state != 'CONFIRMED' for f in scan.findings)}. Only confirmed findings contribute to risk.</p>
<p>Scanner {scan.scanner_version} · Ruleset {scan.ruleset_version} · Risk Engine {scan.risk_engine_version}</p>
{''.join(f"<section><h2>{html.escape(k.title())}: {v}</h2></section>" for k,v in _verification_counts(scan)[0].items())}
<table><tr>{''.join(f'<th>{h}</th>' for h in headers)}</tr>{''.join(rows)}</table></html>"""

def to_sarif(scan: UnifiedScanResult):
    scan=_safe(scan); rules_by_id={}; results=[]
    for f in scan.findings:
        rid=f.rule_id or f.finding_id
        rules_by_id.setdefault(rid,{"id":rid,"name":f.title,"shortDescription":{"text":f.title},"help":{"text":f.remediation or "Review and remediate."}})
        results.append({"ruleId":rid,"level":({"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"none"}.get(f.severity,"note") if f.confirmation_state == "CONFIRMED" else "none"),"message":{"text":f.description},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f.affected_asset or scan.target}}}],"partialFingerprints":{"mirsadFindingId":f.finding_id,"mirsadFingerprint":f.fingerprint},"properties":{"verification":f.verification_status,"confirmation":f.confirmation_state,"assessment_state":f.assessment_state,"confirmation_reason":f.confirmation_reason,"engine":f.source_module,"artifact":f.raw_artifact_id,"engine_result":f.engine_result_id,"execution":f.execution_id}})
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"MIRSAD","version":scan.scanner_version,"rules":list(rules_by_id.values())}},"results":results}]}

def _pdf_paragraph_text(value, language="ar") -> str:
    """Escape untrusted scan-derived text before passing it to ReportLab's Paragraph XML parser."""
    from xml.sax.saxutils import escape
    text = str(value if value is not None else "")
    if language == "ar":
        text = _shape_arabic(text)
    return escape(text)


def to_pdf(scan: UnifiedScanResult, language="ar", audience="technical") -> bytes:
    is_technical = audience not in ("managerial", "non_technical")
    scan = _safe(scan)
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.enums import TA_LEFT
    import os
    buf=io.BytesIO()
    arabic_font_missing = False
    if language == "ar":
        font_path = _find_arabic_font()
        if font_path is None:
            font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
            arabic_font_missing = True
    else:
        font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    if os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("MirsadSans",font_path))
        font="MirsadSans"
    else: font="Helvetica"; arabic_font_missing = language == "ar"
    P = lambda text: _pdf_paragraph_text(text, language)
    def para(text, style):
        return Paragraph(P(text), style)
    doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=28,leftMargin=28,topMargin=28,bottomMargin=28,title=f"MIRSAD {scan.scan_id}")
    styles=getSampleStyleSheet(); styles.add(ParagraphStyle(name="MirsadBody",parent=styles["BodyText"],fontName=font,fontSize=8.5,leading=12)); styles.add(ParagraphStyle(name="MirsadTitle",parent=styles["Title"],fontName=font,fontSize=22,leading=28)); styles.add(ParagraphStyle(name="MirsadH",parent=styles["Heading2"],fontName=font,fontSize=13,leading=17))
    story=[para("MIRSAD — Security Assessment",styles["MirsadTitle"]),para(str(scan.target),styles["MirsadH"]),para(f"Scan ID: {scan.scan_id}",styles["MirsadBody"]),para(f"Status: {scan.status} · Risk: {scan.risk_score}/100 · Coverage: {scan.coverage.percentage:.1f}%",styles["MirsadBody"]),para(f"Scanner {scan.scanner_version} · Ruleset {scan.ruleset_version} · Risk Engine {scan.risk_engine_version}",styles["MirsadBody"]),para(f"Audience: {audience}",styles["MirsadBody"])]
    if arabic_font_missing:
        story.append(para("Note: no Arabic-capable font was found on this server, so Arabic text below may not render correctly. Install a font such as Noto Naskh Arabic to fix this.",styles["MirsadBody"]))
    story.append(PageBreak())
    shown = scan.findings if is_technical else [f for f in scan.findings if f.confirmation_state == "CONFIRMED"]
    sections=[("Scan Metadata",[f"Report ID: {scan.report_metadata.get('report_id','rpt_'+scan.scan_id)}",f"Normalized target: {scan.normalized_target or scan.target}",f"Started: {scan.started_at}",f"Finished: {scan.finished_at}"]), ("Scope",[f"Authentication: {scan.snapshot_metadata.authentication_state if scan.snapshot_metadata else 'unknown'}",f"Modules: {', '.join(scan.snapshot_metadata.modules) if scan.snapshot_metadata else 'unknown'}"]), ("Executive Summary",[f"Confirmed findings: {sum(f.confirmation_state == 'CONFIRMED' for f in scan.findings)}; candidates: {sum(f.confirmation_state != 'CONFIRMED' for f in scan.findings)}",f"Risk score: {scan.risk_score}/100"]), ("Risk",[f"Severity distribution: {', '.join(f'{k}={sum(1 for x in shown if x.severity==k)}' for k in ['Critical','High','Medium','Low','Info'])}"]), ("Coverage",[f"Tested={scan.coverage.tested}; Partial={scan.coverage.partial}; Not tested={scan.coverage.not_tested}; Not configured={scan.coverage.not_configured}; Failed={scan.coverage.failed}; {scan.coverage.percentage:.1f}%"]), ("Pipeline",[f"{k}: {v}" for k,v in scan.pipeline.get('states',{}).items()])]
    for title,items in sections:
        story.append(para(title,styles["MirsadH"])); [story.append(para(str(x),styles["MirsadBody"])) for x in items]; story.append(Spacer(1,6))
    story.append(PageBreak()); story.append(para("Findings",styles["MirsadH"]))
    data=[["Severity","Finding","Asset","Verification","Risk"]]
    for f in shown: data.append([f.severity,P(f.title[:55]),(f.affected_asset or "")[:38],f.confirmation_state,str(f.risk.score)])
    t=Table(data,colWidths=[52,180,125,72,40],repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.35,"grey"),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7)])); story.append(t)
    # Raw evidence (finding IDs, log-line snippets) is technical-audience-only —
    # a managerial/non-technical report only needs the recommended action.
    sections = [("Evidence", "evidence"), ("Recommendations", "remediation")] if is_technical else [("Recommendations", "remediation")]
    for title, attr in sections:
        story.append(PageBreak()); story.append(para(title,styles["MirsadH"]))
        for f in shown:
            label = f"{f.title} — {f.finding_id}" if is_technical else f.title
            story.append(para(label,styles["Heading3"]))
            if attr=="evidence":
                for e in f.evidence[:5]: story.append(para(str(e.evidence)[:1800],styles["MirsadBody"]))
            else: story.append(para(str(f.remediation or "Review and remediate."),styles["MirsadBody"]))
    surface = _surface(scan)
    if is_technical:
        surface_lines = [f"Domain: {surface['domain']}"] + [f"  IP: {x}" for x in surface['ips']] + [f"  Service: {x}" for x in surface['services']] + [f"  Technology: {x}" for x in surface['technologies']]
        for ep in surface['endpoints']:
            surface_lines.append(f"  Endpoint: {ep['url']}")
            surface_lines.extend([f"    Method: {m}" for m in ep['methods']])
            surface_lines.extend([f"    Finding: {f}" for f in ep['findings']])
        tail_sections = [("Assets",[str(scan.assets)]),("Attack Surface",surface_lines),("Limitations",[str(x) for x in (scan.limitations or ["None recorded"]) ]),("Compliance",[str(scan.compliance or {"status":"NOT_ASSESSED"})]),("Report Metadata",[str(scan.report_metadata)])]
    else:
        tail_sections = [("Scope Summary",[f"{len(surface['endpoints'])} endpoint(s) across {len(surface['ips'])} IP address(es)", f"Technologies observed: {', '.join(surface['technologies']) or 'none identified'}"]),("Limitations",[P(str(x)) for x in (scan.limitations or ["None recorded"])])]
    for title,items in tail_sections:
        story.append(PageBreak()); story.append(para(title,styles["MirsadH"])); [story.append(para(x,styles["MirsadBody"])) for x in items]
    doc.build(story); return buf.getvalue()
