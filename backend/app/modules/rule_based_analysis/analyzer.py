"""
modules/rule_based_analysis/analyzer.py

RuleBasedAnalyzer: بديل كامل لـ AIAnalyzer، بنفس الواجهة تماماً (analyze()
تاخد نفس المدخلات وترجع نفس AnalysisReport)، لكن بدون أي استدعاء API خارجي.
كل قرار تصنيف مبني على قواعد صريحة بملف rules.py — قابل للتتبّع 100%،
لا "صندوق أسود"، ونتيجته متطابقة (deterministic) كل مرة لنفس المدخلات.

الهدف من وجود المحرّكين جنب بعض: مقارنة مباشرة بمناقشة مشروع التخرج بين
تحليل AI (فهم سياقي أعمق، لكن غير حتمي) وتحليل rule-based (حتمي وسريع
ومجاني، لكن محدود بما هو مُبرمج مسبقاً فقط).

دعم اللغة (language="ar"|"en"): كل قاعدة بـ rules.py فيها نص عربي ونظيره
الإنجليزي (لاحقة _en). analyze() تختار الحقل المناسب حسب اللغة المطلوبة —
نفس منطق التصنيف، نفس الـ severity، يتغيّر فقط النص المعروض.
"""

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Literal

from app.modules.rule_based_analysis.rules import (
    HEADER_RULES,
    ADDITIONAL_NETWORK_RULES,
    KNOWN_VULNERABLE_VERSIONS,
    RISKY_PORTS,
    TLS_CERT_EXPIRY_WARNING_DAYS,
    VULN_CHECK_RULES,
)
from app.schemas.analysis import AnalysisReport, AnalyzedFinding, Severity
from app.schemas.network import NetworkScanResult
from app.schemas.web import WebScanResult
from app.schemas.api_security import APISecurityResult

ENGINE_NAME = "rule_based"

Language = Literal["ar", "en"]


def _t(rule: dict, key: str, language: Language) -> str:
    """يختار النص المناسب من قاموس قاعدة حسب اللغة (key_en لو language='en')."""
    if language == "en":
        return rule.get(f"{key}_en", rule[key])
    return rule[key]


class RuleBasedAnalyzer:
    def analyze(
        self,
        network_result: NetworkScanResult | None = None,
        web_result: WebScanResult | None = None,
        api_result: APISecurityResult | None = None,
        language: Language = "ar",
    ) -> AnalysisReport:
        if network_result is None and web_result is None and api_result is None:
            raise ValueError("لازم توفّر network_result و/أو web_result على الأقل")

        findings: list[AnalyzedFinding] = []

        if network_result and network_result.status.value == "completed":
            findings.extend(self._analyze_network(network_result, language))

        if web_result and web_result.status.value == "completed":
            findings.extend(self._analyze_web(web_result, language))

        if api_result and api_result.status == "completed":
            findings.extend(self._analyze_api(api_result, language))

        severity_counts = dict(Counter(f.severity.value for f in findings))
        executive_summary = self._build_executive_summary(findings, severity_counts, language)

        score_weights = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 2, Severity.INFO: 0.5}
        raw_score = sum(score_weights.get(f.severity, 0) for f in findings)
        risk_score = round(min(100.0, raw_score * 4.0), 1)
        coverage = {}
        if network_result:
            coverage["network"] = network_result.coverage
        if web_result:
            coverage["web"] = {"crawled_urls": web_result.crawled_urls_count, "forms": web_result.forms_count, "vulnerability_checks": len(web_result.vulnerability_checks), "headers_checked": len(web_result.security_headers)}
        if api_result:
            coverage["api_security"] = api_result.coverage
        top_recommendations = []
        for f in sorted(findings, key=lambda x: list(score_weights.values())[list(score_weights.keys()).index(x.severity)] if x.severity in score_weights else 0, reverse=True)[:5]:
            top_recommendations.append(f.remediation)
        limitations = ["Nmap findings are evidence for review; an NSE result is not automatically a confirmed vulnerability.", "Coverage depends on the selected scan profile and target response."] if language=="en" else ["نتائج Nmap أدلة للفحص والمراجعة؛ نتيجة NSE ليست تلقائياً ثغرة مؤكدة.", "التغطية تعتمد على نوع الفحص واستجابة الهدف."]
        return AnalysisReport(
            report_id=str(uuid.uuid4()),
            engine=ENGINE_NAME,
            generated_at=datetime.now(timezone.utc),
            target_network=network_result.target if network_result else None,
            target_web=web_result.target if web_result else None,
            executive_summary=executive_summary,
            findings=findings,
            total_findings=len(findings),
            severity_counts=severity_counts,
            model_used=None,
            risk_score=risk_score,
            coverage=coverage,
            top_recommendations=top_recommendations,
            limitations=limitations,
        )

    def _analyze_api(self, result: APISecurityResult, language: Language) -> list[AnalyzedFinding]:
        findings: list[AnalyzedFinding] = []
        for match in result.template_matches:
            try:
                severity = Severity(match.severity)
            except ValueError:
                severity = Severity.INFO
            findings.append(AnalyzedFinding(
                finding_id=str(uuid.uuid4()), source_module="api_security",
                title=match.title, severity=severity,
                description=(f"API security check produced evidence on {match.endpoint}." if language == "en" else f"أنتج فحص API دليلاً أمنياً على {match.endpoint}."),
                evidence=match.evidence, remediation=match.remediation, affected_asset=match.endpoint,
                plain_summary=(f"The API showed a security-related condition that should be reviewed." if language == "en" else "أظهر الـ API حالة أمنية تستحق المراجعة."),
                business_impact=("Potential API exposure; validate whether the endpoint is intended to be public." if language == "en" else "قد يوجد تعرّض في واجهة API؛ تحقق من أن جعل الـ endpoint متاحاً مقصود."),
            ))
        for item in result.auth_findings[:30]:
            findings.append(AnalyzedFinding(
                finding_id=str(uuid.uuid4()), source_module="api_security", title="API authentication review",
                severity=Severity.INFO,
                description=item, evidence=item, remediation=("Review authentication and authorization requirements for each API operation." if language == "en" else "راجع متطلبات المصادقة والتفويض لكل عملية API."),
                affected_asset=result.target, plain_summary=item, business_impact=("Authentication coverage needs validation." if language == "en" else "تحتاج تغطية المصادقة إلى تحقق."),
            ))
        return findings

    # -- Network -------------------------------------------------------

    def _analyze_network(self, result: NetworkScanResult, language: Language) -> list[AnalyzedFinding]:
        findings: list[AnalyzedFinding] = []

        for port in result.open_ports:
            matched_cve = self._match_known_vulnerable_version(port.product, port.version)
            if matched_cve:
                if language == "en":
                    description = (
                        f"Detected {port.product} version {port.version} on port "
                        f"{port.port}/{port.protocol}. This version exactly matches a "
                        f"known version with a documented vulnerability."
                    )
                else:
                    description = (
                        f"تم اكتشاف {port.product} إصدار {port.version} على المنفذ "
                        f"{port.port}/{port.protocol}. هذا الإصدار مطابق تماماً لإصدار "
                        f"معروف بثغرة موثّقة."
                    )
                findings.append(
                    AnalyzedFinding(
                        finding_id=str(uuid.uuid4()),
                        source_module="network",
                        title=_t(matched_cve, "title", language),
                        severity=matched_cve["severity"],
                        description=description,
                        evidence=f"port={port.port}/{port.protocol} product={port.product} version={port.version}",
                        remediation=_t(matched_cve, "remediation", language),
                        affected_asset=f"{port.port}/{port.protocol}",
                        plain_summary=_t(matched_cve, "plain_summary", language),
                        business_impact=_t(matched_cve, "business_impact", language),
                    )
                )
                continue  # تجنّب تكرار نفس المنفذ بقاعدة risky_ports العامة

            risky_rule = ADDITIONAL_NETWORK_RULES.get(port.port) or RISKY_PORTS.get(port.port)
            if risky_rule:
                if language == "en":
                    description = (
                        f"Port {port.port}/{port.protocol} is open running "
                        f"{port.service_name or 'an unidentified'} service"
                        + (f" ({port.product} {port.version})" if port.product else "")
                        + ". This port is classified as a default risk source regardless of version."
                    )
                else:
                    description = (
                        f"المنفذ {port.port}/{port.protocol} مفتوح ويشغّل خدمة "
                        f"{port.service_name or 'غير محددة'}"
                        + (f" ({port.product} {port.version})" if port.product else "")
                        + ". هذا المنفذ مصنّف كمصدر خطر افتراضي بغض النظر عن الإصدار."
                    )
                findings.append(
                    AnalyzedFinding(
                        finding_id=str(uuid.uuid4()),
                        source_module="network",
                        title=_t(risky_rule, "title", language),
                        severity=risky_rule["severity"],
                        description=description,
                        evidence=f"port={port.port}/{port.protocol} state={port.state.value}",
                        remediation=_t(risky_rule, "remediation", language),
                        affected_asset=f"{port.port}/{port.protocol}",
                        plain_summary=_t(risky_rule, "plain_summary", language),
                        business_impact=_t(risky_rule, "business_impact", language),
                    )
                )
            else:
                # منفذ مفتوح بدون قاعدة خطر معروفة — يُوثَّق بمستوى Info فقط
                if language == "en":
                    title = f"Open port: {port.service_name or port.port}"
                    description = (
                        f"Port {port.port}/{port.protocol} is open running "
                        f"{port.service_name or 'an unknown'} service. No known risk rule "
                        f"is registered for this port in the current engine."
                    )
                    remediation = "Verify this port is actually required and close it if not necessary."
                    plain_summary = (
                        f"There's a service ({port.service_name or 'unidentified'}) open on the "
                        f"device, with no known risk currently, but it's worth confirming it's actually needed."
                    )
                    business_impact = "Additional exposure surface with no documented risk currently — routine review, not an urgent priority."
                else:
                    title = f"منفذ مفتوح: {port.service_name or port.port}"
                    description = (
                        f"المنفذ {port.port}/{port.protocol} مفتوح ويشغّل خدمة "
                        f"{port.service_name or 'غير معروفة'}. لا توجد قاعدة خطر معروفة "
                        f"مسجّلة لهذا المنفذ بالمحرّك الحالي."
                    )
                    remediation = "تأكد أن هذا المنفذ مطلوب فعلياً وأغلقه إذا لم يكن ضرورياً."
                    plain_summary = (
                        f"في خدمة ({port.service_name or 'غير معروفة'}) مفتوحة على الجهاز، "
                        f"بدون خطر معروف حالياً، لكن يستاهل التأكد إنها مطلوبة فعلاً."
                    )
                    business_impact = "سطح تعرّض إضافي بدون خطر موثّق حالياً — مراجعة روتينية، ليست أولوية عاجلة."

                findings.append(
                    AnalyzedFinding(
                        finding_id=str(uuid.uuid4()),
                        source_module="network",
                        title=title,
                        severity=Severity.INFO,
                        description=description,
                        evidence=f"port={port.port}/{port.protocol}",
                        remediation=remediation,
                        affected_asset=f"{port.port}/{port.protocol}",
                        plain_summary=plain_summary,
                        business_impact=business_impact,
                    )
                )

        for port in result.open_ports:
            for script in port.scripts:
                output_lower = script.output.lower()
                if any(token in output_lower for token in ("vulnerable", "vulners", "cve-", "state: vulnerable")):
                    findings.append(AnalyzedFinding(
                        finding_id=str(uuid.uuid4()), source_module="network",
                        title=f"NSE security finding: {script.script_id}",
                        severity=Severity.HIGH,
                        description=(f"Nmap NSE script {script.script_id} reported security-relevant evidence on {port.port}/{port.protocol}." if language=="en" else f"سكريبت Nmap NSE ‏{script.script_id} أبلغ عن دليل أمني مهم على المنفذ {port.port}/{port.protocol}."),
                        evidence=script.output[:2000], remediation=("Review the NSE evidence, validate the affected service/version, and remediate according to the vendor guidance." if language=="en" else "راجع دليل NSE، وتحقق من الخدمة والإصدار المتأثر، ثم طبّق معالجة المورّد."),
                        affected_asset=f"{port.port}/{port.protocol}", plain_summary=("Nmap found security-relevant evidence that should be validated." if language=="en" else "اكتشف Nmap دليلاً أمنياً يحتاج تحققاً ومعالجة."), business_impact=("Potential service-specific exposure; validation is required before treating it as confirmed." if language=="en" else "قد توجد مخاطرة مرتبطة بالخدمة؛ يجب التحقق قبل اعتبارها ثغرة مؤكدة.")))

        for os_match in result.os_matches[:1]:
            if language == "en":
                title = f"OS fingerprint: {os_match.name}"
                description = f"Network traffic pattern matches {os_match.name} with {os_match.accuracy}% confidence."
                remediation = "No action required — informational only."
                plain_summary = f"We identified the operating system in use ({os_match.name}) — informational only, not an issue."
                business_impact = "Informational finding with no direct severity."
            else:
                title = f"بصمة نظام التشغيل: {os_match.name}"
                description = f"نمط حركة الشبكة يطابق {os_match.name} بنسبة ثقة {os_match.accuracy}%."
                remediation = "لا إجراء مطلوب — معلومة استكشافية فقط."
                plain_summary = f"عرفنا نوع نظام التشغيل المستخدم ({os_match.name}) — معلومة فقط، مو مشكلة."
                business_impact = "معلومة استكشافية بدون خطورة مباشرة."

            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="network",
                    title=title,
                    severity=Severity.INFO,
                    description=description,
                    evidence=f"os_match={os_match.name} accuracy={os_match.accuracy}",
                    remediation=remediation,
                    affected_asset=None,
                    plain_summary=plain_summary,
                    business_impact=business_impact,
                )
            )

        return findings

    def _match_known_vulnerable_version(self, product: str | None, version: str | None) -> dict | None:
        if not product or not version:
            return None
        for entry in KNOWN_VULNERABLE_VERSIONS:
            if entry["product"].lower() == product.lower() and entry["version"] == version:
                return entry
        return None

    # -- Web -------------------------------------------------------------

    def _analyze_web(self, result: WebScanResult, language: Language) -> list[AnalyzedFinding]:
        findings: list[AnalyzedFinding] = []

        if result.tls_info:
            findings.extend(self._analyze_tls(result.tls_info, language))

        for header in result.security_headers:
            if header.present:
                continue
            rule = HEADER_RULES.get(header.header_name)
            if not rule:
                continue
            if language == "en":
                title = f"Missing security header: {header.header_name}"
                description = f"The response does not include a {header.header_name} header."
            else:
                title = f"ترويسة أمنية مفقودة: {header.header_name}"
                description = f"الاستجابة لا تحوي ترويسة {header.header_name}."
            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="web",
                    title=title,
                    severity=rule["severity"],
                    description=description,
                    evidence=f"header={header.header_name} present=false",
                    remediation=_t(rule, "remediation", language),
                    affected_asset=f"header: {header.header_name}",
                    plain_summary=_t(rule, "plain_summary", language),
                    business_impact=_t(rule, "business_impact", language),
                )
            )

        for check in result.vulnerability_checks:
            if not check.vulnerable:
                continue
            rule = VULN_CHECK_RULES.get(check.check_name)
            if not rule:
                continue
            if language == "en":
                description = (
                    f"The {check.check_name} check returned a positive result on parameter "
                    f"'{check.tested_parameter}'."
                )
            else:
                description = (
                    f"فحص {check.check_name} أظهر نتيجة إيجابية على المعامل "
                    f"'{check.tested_parameter}'."
                )
            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="web",
                    title=_t(rule, "title", language),
                    severity=rule["severity"],
                    description=description,
                    evidence=check.evidence or f"payload={check.payload_used}",
                    remediation=_t(rule, "remediation", language),
                    affected_asset=f"parameter: {check.tested_parameter}",
                    plain_summary=_t(rule, "plain_summary", language),
                    business_impact=_t(rule, "business_impact", language),
                )
            )

        if result.server_header:
            if language == "en":
                title = "Server information disclosure (Server header)"
                description = f"The Server header discloses server information: '{result.server_header}'."
                remediation = "Hide or generalize the Server header to reduce information available to an attacker."
                plain_summary = (
                    "The site reveals information about the software it runs, which slightly helps "
                    "an attacker plan their attack."
                )
                business_impact = "Minor information disclosure that helps an attacker target known weaknesses in that specific software."
            else:
                title = "كشف معلومات السيرفر (Server header)"
                description = f"ترويسة Server تكشف معلومات عن السيرفر: '{result.server_header}'."
                remediation = "أخفِ أو عمّم ترويسة Server لتقليل المعلومات المتاحة للمهاجم."
                plain_summary = "الموقع يكشف معلومات عن نوع البرنامج المستخدم بتشغيله، وهذا يسهّل شوي على أي مهاجم يخطط لهجومه."
                business_impact = "كشف معلومات تقنية بسيط يساعد المهاجم على استهداف نقاط ضعف معروفة بذلك البرنامج تحديداً."

            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="web",
                    title=title,
                    severity=Severity.LOW,
                    description=description,
                    evidence=f"Server: {result.server_header}",
                    remediation=remediation,
                    affected_asset="header: Server",
                    plain_summary=plain_summary,
                    business_impact=business_impact,
                )
            )

        return findings

    def _analyze_tls(self, tls_info, language: Language) -> list[AnalyzedFinding]:
        findings: list[AnalyzedFinding] = []

        if not tls_info.enabled:
            if language == "en":
                title = "Connection without TLS/HTTPS encryption"
                description = "The target does not use HTTPS, meaning transmitted data (including potential credentials) is unencrypted."
                remediation = "Enable HTTPS with a valid certificate (e.g. via Let's Encrypt), and redirect all HTTP traffic to HTTPS."
                plain_summary = (
                    "The site doesn't encrypt the connection between the user and the server, meaning "
                    "any data (including passwords) could be seen by anyone monitoring the network."
                )
                business_impact = "Missing basic encryption (HTTPS) exposes every user's data to risk and reduces visitor trust (browsers warn about unsafe sites)."
                evidence = tls_info.error or "TLS not enabled"
            else:
                title = "الاتصال بدون تشفير TLS/HTTPS"
                description = "الهدف لا يستخدم HTTPS، أي أن البيانات المنقولة (بما فيها بيانات اعتماد محتملة) غير مشفّرة."
                remediation = "فعّل HTTPS بشهادة صالحة (مثلاً عبر Let's Encrypt)، وأعد توجيه كل حركة HTTP لـ HTTPS."
                plain_summary = "الموقع ما يشفّر الاتصال بين المستخدم والسيرفر، يعني أي بيانات (بما فيها كلمات مرور) ممكن يشوفها أي شخص يراقب الشبكة."
                business_impact = "غياب التشفير الأساسي (HTTPS) يعرّض بيانات كل مستخدمي الموقع للخطر، ويقلّل ثقة الزوار (المتصفحات تحذّر من المواقع غير الآمنة)."
                evidence = tls_info.error or "TLS غير مفعّل"

            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="web",
                    title=title,
                    severity=Severity.HIGH,
                    description=description,
                    evidence=evidence,
                    remediation=remediation,
                    affected_asset="TLS/HTTPS",
                    plain_summary=plain_summary,
                    business_impact=business_impact,
                )
            )
            return findings

        if tls_info.certificate_valid is False:
            if language == "en":
                title = "Invalid or expired TLS certificate"
                description = "The current TLS certificate is either expired or untrusted."
                remediation = "Renew the TLS certificate immediately from a trusted issuer, and enable auto-renewal if possible."
                plain_summary = "The site's security certificate is expired or untrusted, which makes the browser warn visitors that the site is unsafe."
                business_impact = "An invalid certificate shows visitors a scary browser warning, instantly losing their trust in the site."
                evidence = tls_info.error or "certificate_valid=False"
            else:
                title = "شهادة TLS غير صالحة أو منتهية"
                description = "شهادة TLS الحالية إما منتهية الصلاحية أو غير موثوقة."
                remediation = "جدّد شهادة TLS فوراً من جهة إصدار موثوقة، وفعّل التجديد التلقائي إن أمكن."
                plain_summary = "شهادة الأمان تبع الموقع منتهية أو غير موثوقة، وهذا بيخلّي المتصفح يحذّر الزوار إن الموقع غير آمن."
                business_impact = "شهادة أمان غير صالحة تُظهر تحذيراً مخيفاً للزوار بمتصفحهم، ما يفقد ثقتهم فوراً بالموقع."
                evidence = tls_info.error or "certificate_valid=False"

            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="web",
                    title=title,
                    severity=Severity.HIGH,
                    description=description,
                    evidence=evidence,
                    remediation=remediation,
                    affected_asset="TLS certificate",
                    plain_summary=plain_summary,
                    business_impact=business_impact,
                )
            )
        elif (
            tls_info.days_until_expiry is not None
            and tls_info.days_until_expiry < TLS_CERT_EXPIRY_WARNING_DAYS
        ):
            if language == "en":
                title = "TLS certificate nearing expiry"
                description = f"The TLS certificate will expire in {tls_info.days_until_expiry} days."
                remediation = "Renew the certificate with enough lead time, and enable auto-renewal (e.g. via Certbot)."
                plain_summary = f"The site's security certificate will expire in {tls_info.days_until_expiry} days — it needs renewing before then."
                business_impact = "If the certificate expires, browsers will effectively stop the site from working — needs follow-up before the deadline."
            else:
                title = "شهادة TLS قريبة من الانتهاء"
                description = f"شهادة TLS ستنتهي خلال {tls_info.days_until_expiry} يوم."
                remediation = "جدّد الشهادة قبل انتهائها بوقت كافٍ، وفعّل تجديد تلقائي (مثلاً عبر Certbot)."
                plain_summary = f"شهادة أمان الموقع رح تنتهي خلال {tls_info.days_until_expiry} يوم — لازم تجديدها قبل ما تنتهي."
                business_impact = "انتهاء الشهادة (لو صار) بيوقف عمل الموقع فعلياً بنظر المتصفحات — بيحتاج متابعة قبل الموعد."

            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module="web",
                    title=title,
                    severity=Severity.MEDIUM,
                    description=description,
                    evidence=f"days_until_expiry={tls_info.days_until_expiry}",
                    remediation=remediation,
                    affected_asset="TLS certificate",
                    plain_summary=plain_summary,
                    business_impact=business_impact,
                )
            )

        return findings

    # -- Summary -----------------------------------------------------------

    def _build_executive_summary(
        self, findings: list[AnalyzedFinding], severity_counts: dict[str, int], language: Language
    ) -> str:
        if not findings:
            return (
                "The scan did not reveal any findings requiring documentation under the current rules."
                if language == "en"
                else "لم يُظهر الفحص أي نتائج تستدعي التوثيق وفق القواعد الحالية."
            )

        critical = severity_counts.get(Severity.CRITICAL.value, 0)
        high = severity_counts.get(Severity.HIGH.value, 0)
        medium = severity_counts.get(Severity.MEDIUM.value, 0)
        low = severity_counts.get(Severity.LOW.value, 0)
        info = severity_counts.get(Severity.INFO.value, 0)

        if language == "en":
            parts = [f"A total of {len(findings)} findings were documented by the rule-based analysis engine."]
            if critical or high:
                parts.append(
                    f"There are {critical} Critical and {high} High severity findings requiring immediate remediation."
                )
            if medium:
                parts.append(f"In addition to {medium} Medium severity finding(s).")
            if low or info:
                parts.append(f"And {low + info} Low/Info level finding(s).")
        else:
            parts = [f"تم توثيق {len(findings)} نتيجة إجمالاً بواسطة محرّك التحليل الثابت (rule-based)."]
            if critical or high:
                parts.append(
                    f"يوجد {critical} نتيجة حرجة (Critical) و{high} نتيجة عالية الخطورة (High) "
                    f"تستدعي معالجة فورية."
                )
            if medium:
                parts.append(f"بالإضافة إلى {medium} نتيجة متوسطة الخطورة (Medium).")
            if low or info:
                parts.append(f"و{low + info} نتيجة منخفضة/استكشافية (Low/Info).")

        return " ".join(parts)
