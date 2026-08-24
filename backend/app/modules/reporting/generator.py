from app.schemas.platform import UnifiedScanResult

def generate_markdown(scan: UnifiedScanResult, language="ar"):
    counts={s:sum(1 for f in scan.findings if f.severity==s) for s in ["Critical","High","Medium","Low","Info"]}
    if language=="en":
        lines=[f"# Security Assessment — {scan.target}","",f"**Risk score:** {scan.risk_score}/100",f"**Findings:** {len(scan.findings)}","", "## Executive Summary",f"The assessment discovered {len(scan.findings)} correlated observations. Overall risk is {scan.risk_score}/100.","", "## Severity",*(f"- {k}: {v}" for k,v in counts.items()),"", "## Findings"]
        for i,f in enumerate(scan.findings,1): lines += [f"### {i}. {f.title}",f"- Severity: **{f.severity}**",f"- Confidence: {f.confidence:.0%}",f"- Asset: {f.affected_asset or 'N/A'}",f"- Risk: {f.risk.score}",f"- Evidence: {' | '.join(e.evidence[:800] for e in f.evidence[:3]) or 'N/A'}",f"- Remediation: {f.remediation or 'Review and remediate.'}",f"- References: {', '.join(f.references) or 'N/A'}",""]
        return "\n".join(lines)
    lines=[f"# تقرير التقييم الأمني — {scan.target}","",f"**درجة المخاطر:** {scan.risk_score}/100",f"**عدد النتائج:** {len(scan.findings)}","", "## الملخص التنفيذي",f"اكتشف الفحص {len(scan.findings)} نتيجة مترابطة. درجة المخاطر الإجمالية {scan.risk_score}/100.","", "## توزيع الخطورة",*(f"- {k}: {v}" for k,v in counts.items()),"", "## النتائج"]
    for i,f in enumerate(scan.findings,1): lines += [f"### {i}. {f.title}",f"- الخطورة: **{f.severity}**",f"- الثقة: {f.confidence:.0%}",f"- الأصل: {f.affected_asset or 'غير محدد'}",f"- المخاطر: {f.risk.score}",f"- الدليل: {' | '.join(e.evidence[:800] for e in f.evidence[:3]) or 'غير متوفر'}",f"- المعالجة: {f.remediation or 'راجع الحالة وعالجها.'}",f"- المراجع: {', '.join(f.references) or 'غير متوفر'}",""]
    return "\n".join(lines)
