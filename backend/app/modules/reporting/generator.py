"""Immutable, audit-friendly report generation from a finalized UnifiedScanResult."""
from app.schemas.platform import UnifiedScanResult
from app.core.secret_redaction import redact

def _trend_lines(scan, language="ar"):
    d = scan.scan_diff
    if not d:
        return []
    if language == "en":
        return ["", "## Trend Since Last Scan",
                f"- Compared to previous scan: {d.get('compared_to_scan_id') or 'N/A'}",
                f"- New findings: {d.get('new_count', 0)}", f"- Resolved since last scan: {d.get('resolved_count', 0)}",
                f"- Persisting (still open): {d.get('persisting_count', 0)}",
                "- Note: a finding not detected this time usually means it was fixed, but can also mean reduced coverage this run — cross-check the Coverage section above before treating something as resolved."]
    return ["", "## التغيير منذ آخر فحص",
            f"- الفحص السابق للمقارنة: {d.get('compared_to_scan_id') or 'غير متوفر'}",
            f"- اكتشافات جديدة: {d.get('new_count', 0)}", f"- تم إصلاحها منذ آخر فحص: {d.get('resolved_count', 0)}",
            f"- لسا موجودة: {d.get('persisting_count', 0)}",
            "- ملاحظة: اختفاء finding من هذا الفحص عادة يعني إنه انصلح، لكن ممكن كمان يعني تغطية أقل بهذا الفحص — راجع قسم التغطية أعلاه قبل ما تعتبره مُصلَحاً."]


def _oob_lines(scan, language="ar"):
    probes = getattr(getattr(scan, "web_scan", None), "oob_probes", None) or []
    if not probes:
        return []
    if language == "en":
        lines = ["", "## Out-of-Band Probes Sent (manual verification required)",
                 "These were not auto-confirmed — check your OOB provider's dashboard for an interaction matching each correlation ID within this scan's time window."]
        for p in probes[:20]:
            lines.append(f"- `{p.get('correlation_id')}` — parameter `{p.get('parameter')}` at {p.get('url')} (sent {p.get('sent_at')})")
        return lines
    lines = ["", "## احتمالات OOB المُرسَلة (تحتاج تحقق يدوي)",
             "لم تُؤكَّد تلقائياً — راجع لوحة تحكم مزوّد OOB عندك عن أي تفاعل يطابق كل معرّف ضمن الفترة الزمنية لهذا الفحص."]
    for p in probes[:20]:
        lines.append(f"- `{p.get('correlation_id')}` — الباراميتر `{p.get('parameter')}` بـ {p.get('url')} (أُرسل {p.get('sent_at')})")
    return lines



def _subdomain_lines(scan, language="ar"):
    records = getattr(scan, "subdomains", None) or []
    if language == "en":
        lines = ["## Discovered Subdomains"]
        if not records: return lines + ["- No in-scope subdomains were discovered."]
        for r in records:
            lines.append(f"- `{r.get('hostname')}` — method: {r.get('method','unknown')} — source: {r.get('source','unknown')}")
            if r.get("status"): lines.append(f"  - Status: {r['status']}")
            if r.get("tests"): lines.append("  - Tests: " + ", ".join(f"{k}={v}" for k,v in r["tests"].items()))
            if r.get("evidence"): lines.append(f"  - Evidence: {r['evidence']}")
        return lines
    lines = ["## النطاقات الفرعية المكتشفة"]
    if not records: return lines + ["- لم يتم اكتشاف نطاقات فرعية ضمن النطاق."]
    for r in records:
        lines.append(f"- `{r.get('hostname')}` — الطريقة: {r.get('method','غير معروفة')} — المصدر: {r.get('source','غير معروف')}")
        if r.get("status"): lines.append(f"  - الحالة: {r['status']}")
        if r.get("tests"): lines.append("  - الفحوصات: " + ", ".join(f"{k}={v}" for k,v in r["tests"].items()))
        if r.get("evidence"): lines.append(f"  - الدليل: {r['evidence']}")
    return lines

def _assessment_policy_lines(scan, language="ar"):
    policy = (scan.pipeline or {}).get("assessment_policy") or {}
    if language == "en":
        return ["## Assessment Policy",
                f"- Profile: {policy.get('profile', 'standard')}",
                f"- Safety mode: {policy.get('safe_mode', 'safe')}",
                f"- Network scan: {'selected' if policy.get('network', True) else 'not selected'}",
                f"- Web scan: {'selected' if policy.get('web', True) else 'not selected'}",
                f"- API security: {'selected' if policy.get('api', True) else 'not selected'}",
                f"- Subdomain discovery: {'selected' if policy.get('subdomain_discovery', True) else 'not selected'}",
                f"- Subdomain DNS verification: {'selected' if policy.get('subdomain_dns_verification', True) else 'not selected'}",
                f"- Subdomain network scan: {'selected' if policy.get('subdomain_network_scan', True) else 'not selected'}",
                f"- Subdomain web scan: {'selected' if policy.get('subdomain_web_scan', True) else 'not selected'}",
                f"- Subdomain API security: {'selected' if policy.get('subdomain_api_security', True) else 'not selected'}",
                f"- Low-value hardening findings: {'included' if policy.get('include_hardening_findings', False) else 'filtered from Findings'}"]
    return ["## سياسة التقييم",
            f"- Profile: {policy.get('profile', 'standard')}",
            f"- وضع الأمان: {policy.get('safe_mode', 'safe')}",
            f"- فحص الشبكة: {'محدد' if policy.get('network', True) else 'غير محدد'}",
            f"- فحص الويب: {'محدد' if policy.get('web', True) else 'غير محدد'}",
            f"- فحص API: {'محدد' if policy.get('api', True) else 'غير محدد'}",
            f"- اكتشاف النطاقات الفرعية: {'محدد' if policy.get('subdomain_discovery', True) else 'غير محدد'}",
            f"- التحقق من DNS للنطاقات الفرعية: {'محدد' if policy.get('subdomain_dns_verification', True) else 'غير محدد'}",
            f"- فحص الشبكة للنطاقات الفرعية: {'محدد' if policy.get('subdomain_network_scan', True) else 'غير محدد'}",
            f"- فحص الويب للنطاقات الفرعية: {'محدد' if policy.get('subdomain_web_scan', True) else 'غير محدد'}",
            f"- فحص API للنطاقات الفرعية: {'محدد' if policy.get('subdomain_api_security', True) else 'غير محدد'}",
            f"- نتائج Hardening منخفضة القيمة: {'مشمولة' if policy.get('include_hardening_findings', False) else 'مستبعدة من Findings وتبقى ضمن بيانات القياس'}"]


def _intel_lines_en(f):
    lines=[]
    if f.cwe: lines.append(f"- CWE: {f.cwe.get('id')} — {f.cwe.get('name')}")
    if f.mitre_attack: lines.append("- MITRE ATT&CK: " + "; ".join(t.get("id","") for t in f.mitre_attack))
    if f.cve_matches: lines.append("- CVE: " + ", ".join(str(c.get("cve_id")) for c in f.cve_matches))
    return lines



def _source_intelligence_lines(scan, language="ar"):
    web = getattr(scan, "web_scan", None)
    si = getattr(web, "source_intelligence", {}) or {}
    if not si:
        return []
    coverage = si.get("coverage") or {}
    techs = si.get("technologies") or []
    findings = si.get("findings") or []
    detectors = si.get("detectors") or {}
    if language == "en":
        lines=["## Source Intelligence Findings",
               f"- Status: {si.get('status','UNKNOWN')}",
               f"- HTML pages: {coverage.get('html_pages',0)}",
               f"- JavaScript assets: {coverage.get('js_assets',0)}",
               f"- Source maps analyzed: {coverage.get('source_maps',0)}",
               f"- Source-derived endpoints: {coverage.get('endpoints',0)}",
               f"- Secret candidates (redacted): {coverage.get('secret_candidates',0)}",
               f"- Technologies: {', '.join(str(x.get('name')) for x in techs if isinstance(x,dict) and x.get('name')) or 'None'}"]
        if detectors:
            lines.append("- Detectors: " + ", ".join(f"{k}={v.get('status','UNKNOWN') if isinstance(v,dict) else 'UNKNOWN'}" for k,v in detectors.items() if k!="correlated_secrets"))
        for f in findings:
            lines.append(f"- {f.get('title','Source observation')} — {f.get('severity','Info')} — confidence {float(f.get('confidence',0) or 0):.0%} — evidence: {f.get('evidence_redacted','REDACTED')}")
        return lines
    lines=["## نتائج Source Intelligence",
           f"- الحالة: {si.get('status','غير معروفة')}",
           f"- صفحات HTML: {coverage.get('html_pages',0)}",
           f"- ملفات JavaScript: {coverage.get('js_assets',0)}",
           f"- Source Maps المحللة: {coverage.get('source_maps',0)}",
           f"- Endpoints مستخرجة من المصدر: {coverage.get('endpoints',0)}",
           f"- مؤشرات الأسرار (مخفاة): {coverage.get('secret_candidates',0)}",
           f"- التقنيات: {', '.join(str(x.get('name')) for x in techs if isinstance(x,dict) and x.get('name')) or 'لا يوجد'}"]
    if detectors:
        lines.append("- الأدوات: " + ", ".join(f"{k}={v.get('status','UNKNOWN') if isinstance(v,dict) else 'UNKNOWN'}" for k,v in detectors.items() if k!="correlated_secrets"))
    for f in findings:
        lines.append(f"- {f.get('title','ملاحظة Source Intelligence')} — {f.get('severity','Info')} — الثقة {float(f.get('confidence',0) or 0):.0%} — الدليل: {f.get('evidence_redacted','REDACTED')}")
    return lines

def _engine_results_lines(scan, language="ar"):
    """Per-tool outcome table: what each engine actually did, so an empty result
    can be told apart from a skipped/failed/passive-only run."""
    ext = getattr(scan, "external_scanners", None) or {}
    adv = getattr(scan, "advanced_security", None) or {}
    en = language == "en"
    lines = ["## Per-Tool Results" if en else "## نتائج كل أداة على حدة"]
    rows = []
    for name, payload in ext.items():
        if not isinstance(payload, dict):
            continue
        findings = payload.get("findings") or []
        sev = {}
        for f in findings:
            k = str(f.get("severity") or f.get("risk") or "Info").title() if isinstance(f, dict) else "Info"
            sev[k] = sev.get(k, 0) + 1
        dur = payload.get("duration_seconds")
        extra = []
        if payload.get("mode"): extra.append(f"mode={payload['mode']}")
        if payload.get("authenticated") is not None: extra.append(f"authenticated={bool(payload['authenticated'])}")
        if payload.get("targets_tested"): extra.append(f"targets_tested={len(payload['targets_tested'])}")
        if payload.get("template_count"): extra.append(f"templates={payload['template_count']}")
        rows.append((name, str(payload.get("status", "UNKNOWN")), len(findings), sev,
                     f"{float(dur):.0f}s" if isinstance(dur, (int, float)) else "n/a",
                     "; ".join(extra), str(payload.get("reason") or payload.get("auth_warning") or "")[:300]))
    if isinstance(adv, dict) and adv:
        rows.append(("advanced_security", str(adv.get("status", "UNKNOWN")), len(adv.get("findings") or []), {}, "n/a", "", str(adv.get("reason") or "")[:300]))
    if not rows:
        return lines + ["- No external engine results were recorded." if en else "- لم تُسجَّل نتائج لأي أداة خارجية."]
    for name, status, n, sev, dur, extra, reason in rows:
        sev_txt = ", ".join(f"{k}={v}" for k, v in sorted(sev.items())) or "-"
        if en:
            lines.append(f"- **{name}** — status: {status} — raw findings: {n} ({sev_txt}) — duration: {dur}" + (f" — {extra}" if extra else "") + (f" — note: {reason}" if reason else ""))
        else:
            lines.append(f"- **{name}** — الحالة: {status} — نتائج خام: {n} ({sev_txt}) — المدة: {dur}" + (f" — {extra}" if extra else "") + (f" — ملاحظة: {reason}" if reason else ""))
    lines.append("- A tool with status SKIPPED/UNAVAILABLE/FAILED, or 0 raw findings in passive mode, does NOT mean the target is clean." if en else "- أداة بحالة SKIPPED/UNAVAILABLE/FAILED، أو بصفر نتائج في الوضع السلبي، لا تعني أن الهدف سليم.")
    return lines

def _counts(scan):
    # Severity distribution describes confirmed security issues only.
    return {s: sum(1 for f in scan.findings if f.severity == s and
                   f.confirmation_state == "CONFIRMED" and
                   f.category not in {"hardening-observation", "deployment-context"})
            for s in ["Critical", "High", "Medium", "Low", "Info"]}


def _candidate_lines(scan, language="ar"):
    candidates = [f for f in scan.findings if f.confirmation_state != "CONFIRMED"]
    if language == "en":
        lines = ["", "## Candidates (not confirmed vulnerabilities)",
                 f"- Unconfirmed observations: {len(candidates)}"]
        for f in candidates:
            lines.append(f"- {f.title} [{f.severity} signal] — {f.affected_asset or 'unknown'}; "
                         f"assessment: {f.assessment_state}; confirmation blocker: {f.confirmation_reason or 'independent proof missing'}")
    else:
        lines = ["", "## النتائج المرشحة (ليست ثغرات مؤكدة)",
                 f"- ملاحظات غير مؤكدة: {len(candidates)}"]
        for f in candidates:
            lines.append(f"- {f.title} [إشارة {f.severity}] — {f.affected_asset or 'غير معروف'}؛ "
                         f"التصنيف: {f.assessment_state}؛ سبب عدم التأكيد: {f.confirmation_reason or 'لا يوجد دليل مستقل كافٍ'}")
    return lines


def _endpoint_coverage_lines(scan, language="ar"):
    matrix = scan.coverage.endpoint_matrix
    if language == "en":
        lines = ["", "## Endpoint Coverage (discovery is not security testing)"]
    else:
        lines = ["", "## تغطية نقاط النهاية (الاكتشاف ليس اختبارًا أمنيًا)"]
    if not matrix:
        return lines + ["- No endpoint-level evidence was available." if language == "en"
                        else "- لم تتوفر أدلة تفصيلية على نقاط النهاية."]
    tested = sum(e.get("security_state") == "TESTED" for e in matrix)
    lines.append(f"- {tested}/{len(matrix)} endpoint/method pairs with a recorded security test")
    for item in matrix[:200]:
        lines.append(f"- {item.get('method','GET')} {item.get('url','')} — "
                     f"{item.get('security_state','NOT_TESTED')}: {item.get('reason','')}")
    if len(matrix) > 200:
        lines.append(f"- {len(matrix)-200} additional rows available in JSON export")
    return lines


def _attack_surface(scan):
    """Build a real hierarchical attack-surface view from the immutable snapshot."""
    domain = scan.normalized_target or scan.target
    ips = list(scan.assets[0].get("ips", [])) if scan.assets and isinstance(scan.assets[0], dict) else list(scan.dns.get("addresses", scan.dns.get("ips", [])) or [])
    services = list(scan.assets[0].get("services", [])) if scan.assets and isinstance(scan.assets[0], dict) else []
    technologies = list(scan.technologies or (scan.assets[0].get("technologies", []) if scan.assets and isinstance(scan.assets[0], dict) else []))
    endpoints = []
    for e in (scan.web_scan.endpoints if scan.web_scan and hasattr(scan.web_scan, "endpoints") else []):
        methods = list(getattr(e, "methods", []) or [])
        endpoints.append({"url": getattr(e, "url", str(e)), "methods": methods, "findings": [f.finding_id for f in scan.findings if (f.affected_asset or "") == getattr(e, "url", str(e))]})
    for f in scan.findings:
        asset = f.affected_asset or ""
        if asset.startswith("http") and not any(x["url"] == asset for x in endpoints):
            endpoints.append({"url": asset, "methods": [], "findings": [f.finding_id]})
    return {"domain": domain, "ips": sorted(set(map(str, ips))), "services": sorted(set(map(str, services))),
            "technologies": sorted(set(map(str, technologies))), "endpoints": endpoints,
            "findings": [f.finding_id for f in scan.findings]}

def _attack_surface_lines(scan, indent=""):
    surface = _attack_surface(scan); lines=[f"- Domain: {surface['domain']}"]
    for ip in surface["ips"]: lines.append(f"  - IP: {ip}")
    for service in surface["services"]: lines.append(f"  - Service: {service}")
    for tech in surface["technologies"]: lines.append(f"  - Technology: {tech}")
    for ep in surface["endpoints"]:
        lines.append(f"  - Endpoint: {ep['url']}")
        for method in ep["methods"]: lines.append(f"    - Method: {method}")
        for fid in ep["findings"]: lines.append(f"    - Finding: {fid}")
    return lines

_SCOPED_NEGATIVE = {
    "en": "A vulnerability class not listed as confirmed was not proven within the covered endpoints and parameters only (see Endpoint Coverage); this is not a statement that it is absent.",
    "ar": "عدم ظهور فئة ثغرة ضمن النتائج المؤكدة يعني أنها لم تُثبت ضمن نقاط النهاية والمعاملات المغطاة فقط (انظر تغطية نقاط النهاية)، ولا يعني غيابها.",
}

def _limitations(scan, language="ar"):
    return (scan.limitations or ["No additional limitations were recorded."]) + [_SCOPED_NEGATIVE[language]]

def _priority_lines(scan, language="ar"):
    ordered = sorted((f for f in scan.findings if f.confirmation_state == "CONFIRMED"), key=lambda f: (str(getattr(f, "priority", "P4")), -float(getattr(getattr(f, "risk", None), "score", 0) or 0)))
    top = [f for f in ordered if getattr(f, "priority", "P4") in {"P1", "P2"}][:5]
    if language == "en":
        lines = ["## Remediation Roadmap"]
        if not top: return lines + ["- No P1/P2 remediation items were generated."]
        for f in top:
            assets = getattr(f, "affected_assets", None) or ([f.affected_asset] if f.affected_asset else [])
            lines.append(f"- **{getattr(f, 'priority', 'P3')}** — {f.title} — {f.severity} — {len(set(assets))} affected asset(s)")
            lines.append(f"  - Action: {f.remediation or 'Review and remediate.'}")
        return lines
    lines = ["## خارطة المعالجة ذات الأولوية"]
    if not top: return lines + ["- لا توجد عناصر P1/P2 تتطلب معالجة عاجلة."]
    for f in top:
        assets = getattr(f, "affected_assets", None) or ([f.affected_asset] if f.affected_asset else [])
        lines.append(f"- **{getattr(f, 'priority', 'P3')}** — {f.title} — {f.severity} — {len(set(assets))} أصل متأثر")
        lines.append(f"  - الإجراء: {f.remediation or 'راجع الحالة وعالجها.'}")
    return lines

def generate_markdown(scan: UnifiedScanResult, language="ar", audience="technical"):
    """audience: 'technical' (full detail — IDs, rule IDs, fingerprints, raw
    evidence, raw asset dump) or 'managerial'/'non_technical' (condensed —
    title, severity, business-friendly remediation only, no raw evidence or
    internal identifiers)."""
    is_technical = audience not in ("managerial", "non_technical")
    confirmed = [f for f in scan.findings if f.confirmation_state == "CONFIRMED"]
    c=_counts(scan); p=scan.pipeline.get("states",{})
    if language=="en":
        lines=[f"# MIRSAD Security Assessment — {scan.target}","", "## Scan Metadata",f"- Scan ID: {scan.scan_id}",f"- Report ID: {scan.report_metadata.get('report_id','rpt_'+scan.scan_id)}",f"- Normalized target: {scan.normalized_target or scan.target}",f"- Status: {scan.status}",f"- Started: {scan.started_at}",f"- Finished: {scan.finished_at}",f"- Scanner: {scan.scanner_version}",f"- Ruleset: {scan.ruleset_version}",f"- Risk engine: {scan.risk_engine_version}","", "## Scope",f"- Target: {scan.target}",f"- Authentication: {scan.snapshot_metadata.authentication_state if scan.snapshot_metadata else 'unknown'}",f"- Modules: {', '.join(scan.snapshot_metadata.modules) if scan.snapshot_metadata else 'unknown'}","", "## Executive Summary",f"Confirmed-only risk score: **{scan.risk_score}/100**",f"Confirmed: {len(confirmed)}; candidates: {len(scan.findings)-len(confirmed)}. Candidate signals cannot raise this score.","", "## Risk",f"- Risk score: {scan.risk_score}/100",f"- Evidence quality is included in each finding risk assessment.","- Severity distribution: " + ", ".join(f"{k}={v}" for k,v in c.items()),"", "## Coverage",f"- Tested: {scan.coverage.tested}",f"- Partial: {scan.coverage.partial}",f"- Not tested: {scan.coverage.not_tested}",f"- Not configured: {scan.coverage.not_configured}",f"- Failed: {scan.coverage.failed}",f"- Coverage: {scan.coverage.percentage:.1f}%","", "## Pipeline"]
        for k,v in p.items(): lines.append(f"- {k}: {v}")
        lines += _trend_lines(scan, "en")
        lines += _oob_lines(scan, "en")
        lines += [""] + _assessment_policy_lines(scan, "en") + [""] + _priority_lines(scan, "en")
        lines += [""] + _subdomain_lines(scan, "en") + [""] + _source_intelligence_lines(scan, "en") + [""] + _engine_results_lines(scan, "en") + ["", "## Confirmed Findings"] + _endpoint_coverage_lines(scan, "en")
        for i,f in enumerate(confirmed,1):
            if is_technical:
                lines += [f"### {i}. {f.title}",f"- ID: {f.finding_id}",f"- Rule: {f.rule_id}",f"- Tool version: {f.tool_version or 'N/A'}",f"- Severity: **{f.severity}**",f"- Priority: {getattr(f, 'priority', 'P3')}",f"- Confidence: {f.confidence:.0%}",f"- Status: {f.status}",f"- Verification: {f.verification_status}",f"- Verification ID: {getattr(f, 'verification_id', None) or 'N/A'}",f"- Verification method: {getattr(f, 'verification_method', None) or 'N/A'}",f"- Verification timestamp: {getattr(f, 'verification_timestamp', None) or 'N/A'}",f"- Replay: {f.verification_replay or 'N/A'}",f"- Security impact: {f.security_impact or 'N/A'}",f"- Independent verification: {f.independent_verification or 'N/A'}",f"- Raw artifact: /api/v1/platform/scans/{scan.scan_id}/artifacts/{f.raw_artifact_id} (sha256={f.raw_artifact_sha256})" if f.raw_artifact_id else "- Raw artifact: N/A",f"- Asset: {f.affected_asset or 'N/A'}",f"- Endpoint: {f.endpoint_id or 'N/A'}",f"- Risk contribution: {f.risk_contribution}",f"- Fingerprint: {f.fingerprint}",f"- Observations: {f.observation_count}",f"- Evidence count: {f.evidence_count}",f"- Discovery method: {getattr(f, 'discovery_method', None) or 'N/A'}",f"- Executed command: {getattr(f, 'discovery_command', None) or 'N/A'}",f"- Potential impact: {getattr(f, 'impact', None) or 'N/A'}",f"- Exploitability: {getattr(f, 'exploitability', None) or 'N/A'}"]
                lines += ["- Evidence: " + (" | ".join(e.evidence[:1000] for e in f.evidence[:5]) or "N/A"), f"- Remediation: {f.remediation or 'Review and remediate.'}"] + _intel_lines_en(f) + [""]
            else:
                lines += [f"### {i}. {f.title}",f"- Severity: **{f.severity}**",f"- Affected area: {f.affected_asset or 'N/A'}",f"- Recommended action: {f.remediation or 'Review and remediate.'}",""]
        lines += _candidate_lines(scan, "en")
        if is_technical:
            lines += ["## Assets",str(scan.assets),"", "## Attack Surface"] + _attack_surface_lines(scan)
        else:
            surface = _attack_surface(scan)
            lines += ["## Assets in Scope", f"- {len(surface['endpoints'])} endpoint(s) across {len(surface['ips'])} IP address(es)", f"- Technologies observed: {', '.join(surface['technologies']) or 'none identified'}"]
        lines += ["", "## Recommendations"]
        for f in confirmed: lines.append(f"- {f.title}: {f.remediation or 'Review and remediate.'}" if not is_technical else f"- {f.finding_id}: {f.remediation or 'Review and remediate.'}")
        lines += ["", "## Limitations"] + [f"- {x}" for x in _limitations(scan, "en")]
        lines += ["", "## Compliance", str(scan.compliance or {"status":"NOT_ASSESSED"}), "", "## Report Metadata", str(scan.report_metadata)]
        return redact("\n".join(lines))
    lines=[f"# تقرير MIRSAD الأمني — {scan.target}","", "## بيانات الفحص",f"- Scan ID: {scan.scan_id}",f"- Report ID: {scan.report_metadata.get('report_id','rpt_'+scan.scan_id)}",f"- الهدف الموحّد: {scan.normalized_target or scan.target}",f"- الحالة: {scan.status}",f"- Scanner: {scan.scanner_version}",f"- Ruleset: {scan.ruleset_version}",f"- Risk Engine: {scan.risk_engine_version}","", "## الملخص التنفيذي",f"درجة مخاطر النتائج المؤكدة فقط: **{scan.risk_score}/100**",f"النتائج المؤكدة: {len(confirmed)}؛ مرشحات تحتاج تحقق: {len(scan.findings)-len(confirmed)}.","", "## المخاطر",f"- Risk: {scan.risk_score}/100", "- التوزيع: " + ", ".join(f"{k}={v}" for k,v in c.items()),"", "## التغطية",f"- Tested: {scan.coverage.tested}",f"- Partial: {scan.coverage.partial}",f"- Not Tested: {scan.coverage.not_tested}",f"- Not Configured: {scan.coverage.not_configured}",f"- Failed: {scan.coverage.failed}",f"- Coverage: {scan.coverage.percentage:.1f}%","", "## Pipeline"]
    for k,v in p.items(): lines.append(f"- {k}: {v}")
    lines += _trend_lines(scan, "ar")
    lines += _oob_lines(scan, "ar")
    lines += [""] + _priority_lines(scan, "ar") + [""] + _subdomain_lines(scan, "ar") + [""] + _source_intelligence_lines(scan, "ar") + [""] + _engine_results_lines(scan, "ar") + ["", "## النتائج المؤكدة"] + _endpoint_coverage_lines(scan, "ar")
    for i,f in enumerate(confirmed,1):
        if is_technical:
            lines += [f"### {i}. {f.title}",f"- ID: {f.finding_id}",f"- Rule: {f.rule_id}",f"- الخطورة: **{f.severity}**",f"- الأولوية: {getattr(f, 'priority', 'P3')}",f"- الثقة: {f.confidence:.0%}",f"- الحالة: {f.status}",f"- التحقق: {f.verification_status}",f"- الأصل: {f.affected_asset or 'غير محدد'}",f"- المساهمة في المخاطر: {f.risk_contribution}",f"- إعادة التحقق: {f.verification_replay or 'غير متوفر'}",f"- الأثر المثبت: {f.security_impact or 'غير متوفر'}",f"- التحقق المستقل: {f.independent_verification or 'غير متوفر'}",f"- الأثر الخام: /api/v1/platform/scans/{scan.scan_id}/artifacts/{f.raw_artifact_id} (sha256={f.raw_artifact_sha256})" if f.raw_artifact_id else "- الأثر الخام: غير متوفر",f"- Fingerprint: {f.fingerprint}",f"- Observations: {f.observation_count}",f"- Evidence: {f.evidence_count}",f"- طريقة الاكتشاف: {getattr(f, 'discovery_method', None) or 'غير محدد'}",f"- الأمر المنفذ فعلياً: {getattr(f, 'discovery_command', None) or 'غير متوفر'}",f"- الأثر المحتمل: {getattr(f, 'impact', None) or 'غير محدد'}",f"- قابلية الاستغلال: {getattr(f, 'exploitability', None) or 'غير محددة'}","- الدليل: " + (" | ".join(e.evidence[:1000] for e in f.evidence[:5]) or "غير متوفر"),f"- المعالجة: {f.remediation or 'راجع الحالة وعالجها.'},",""]
        else:
            lines += [f"### {i}. {f.title}",f"- الخطورة: **{f.severity}**",f"- المنطقة المتأثرة: {f.affected_asset or 'غير محدد'}",f"- الإجراء المقترح: {f.remediation or 'راجع الحالة وعالجها.'}",""]
    lines += _candidate_lines(scan, "ar")
    if is_technical:
        lines += ["## الأصول",str(scan.assets),"", "## Attack Surface"] + _attack_surface_lines(scan)
    else:
        surface = _attack_surface(scan)
        lines += ["## نطاق الأصول", f"- {len(surface['endpoints'])} نقطة نهاية عبر {len(surface['ips'])} عنوان IP", f"- التقنيات المكتشفة: {', '.join(surface['technologies']) or 'لا يوجد'}"]
    lines += ["", "## التوصيات"] + ([f"- {f.finding_id}: {f.remediation or 'راجع الحالة وعالجها.'}" for f in confirmed] if is_technical else [f"- {f.title}: {f.remediation or 'راجع الحالة وعالجها.'}" for f in confirmed]) + ["", "## القيود"] + [f"- {x}" for x in _limitations(scan, "ar")] + ["", "## Compliance", str(scan.compliance or {"status":"NOT_ASSESSED"}), "", "## بيانات التقرير", str(scan.report_metadata)]
    return redact("\n".join(lines))
