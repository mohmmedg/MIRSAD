import csv, html, io
from app.schemas.platform import UnifiedScanResult

def to_json(scan: UnifiedScanResult): return scan.model_dump(mode="json")

def to_csv(scan: UnifiedScanResult) -> str:
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(["finding_id","severity","confidence","title","asset","risk","description","remediation","evidence","references"])
    for f in scan.findings:
        w.writerow([f.finding_id,f.severity,f.confidence,f.title,f.affected_asset or "",f.risk.score,f.description,f.remediation," | ".join(e.evidence[:1000] for e in f.evidence)," | ".join(f.references)])
    return out.getvalue()

def to_html(scan: UnifiedScanResult, language="ar"):
    title="Security Assessment" if language=="en" else "التقييم الأمني"
    rows=[]
    for f in scan.findings:
        ev="<br>".join(html.escape(e.evidence[:1200]) for e in f.evidence[:3])
        rows.append(f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.affected_asset or '')}</td><td>{ev}</td><td>{f.risk.score}</td></tr>")
    return f"<!doctype html><html lang='{language}'><meta charset='utf-8'><title>{html.escape(title)}</title><style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.5rem;text-align:left}}@media print{{body{{margin:.5rem}}}}</style><h1>{html.escape(title)} — {html.escape(scan.target)}</h1><p>Risk score: {scan.risk_score}/100 · Findings: {len(scan.findings)}</p><table><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Evidence</th><th>Risk</th></tr>{''.join(rows)}</table></html>"

def to_sarif(scan: UnifiedScanResult):
    rules=[]; results=[]; seen=set()
    for f in scan.findings:
        if f.finding_id not in seen:
            seen.add(f.finding_id); rules.append({"id":f.finding_id,"name":f.title,"shortDescription":{"text":f.title},"help":{"text":f.remediation or "Review and remediate."}})
        results.append({"ruleId":f.finding_id,"level":{"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"none"}.get(f.severity,"note"),"message":{"text":f.description},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f.affected_asset or scan.target}}}]})
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"MIRSAD","rules":rules}},"results":results}]}

def to_pdf(scan: UnifiedScanResult, language="ar") -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=30,leftMargin=30,topMargin=30,bottomMargin=30); styles=getSampleStyleSheet(); story=[Paragraph(html.escape(("Security Assessment" if language=="en" else "التقييم الأمني")+" — "+scan.target),styles["Title"]),Paragraph(f"Risk score: {scan.risk_score}/100 | Findings: {len(scan.findings)}",styles["BodyText"]),Spacer(1,12)]
    data=[["Severity","Finding","Asset","Risk"]]+[[f.severity,f.title,f.affected_asset or "",str(f.risk.score)] for f in scan.findings]
    t=Table(data,repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.5,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(t); doc.build(story); return buf.getvalue()
