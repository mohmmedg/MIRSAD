"""
modules/rule_based_analysis/report_formatter.py

ReportFormatter: يحوّل AnalysisReport (نتيجة RuleBasedAnalyzer.analyze) إلى
FormattedReport بصياغة تناسب جمهوراً محدداً (AudienceLevel) وبلغة محدّدة
(language)، بدون أي تغيير على الـ findings الأصلية أو تصنيف الخطورة —
فقط طريقة العرض والمحتوى واللغة تختلف.

المصدر الوحيد للصياغات الثلاث هو نفسه (rules.py عبر AnalyzedFinding.plain_summary
و business_impact، بنسختيهما العربية والإنجليزية)، فما في تكرار منطق أو
احتمال تناقض بين التقارير.

ملاحظة: هذا يفترض أن AnalyzedFinding الممرّرة أصلاً وُلّدت باللغة المطلوبة
(عبر RuleBasedAnalyzer.analyze(language=...)) — الـ formatter نفسه لا يترجم
نصوص الـ findings، فقط يبني حولها الهيكل النصي (عناوين، تسميات، جمل ربط)
باللغة المطلوبة.
"""

from typing import Literal

from app.schemas.analysis import AnalysisReport, AnalyzedFinding, AudienceLevel, FormattedReport, Severity

Language = Literal["ar", "en"]

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

SEVERITY_LABELS = {
    "ar": {
        Severity.CRITICAL: "حرجة",
        Severity.HIGH: "عالية",
        Severity.MEDIUM: "متوسطة",
        Severity.LOW: "منخفضة",
        Severity.INFO: "استكشافية",
    },
    "en": {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Info",
    },
}

RISK_LABELS = {
    "ar": {
        "very_high": "خطر مرتفع جداً — يتطلب تدخّلاً فورياً",
        "high": "خطر مرتفع — يتطلب معالجة عاجلة",
        "medium": "خطر متوسط — يستحق جدولة معالجة قريبة",
        "low": "خطر منخفض — تحسينات موصى بها",
        "none": "لا يوجد خطر جوهري بحسب القواعد الحالية",
    },
    "en": {
        "very_high": "Very High Risk — requires immediate intervention",
        "high": "High Risk — requires urgent remediation",
        "medium": "Medium Risk — worth scheduling remediation soon",
        "low": "Low Risk — improvements recommended",
        "none": "No material risk under the current rules",
    },
}


def _sort_by_severity(findings: list[AnalyzedFinding]) -> list[AnalyzedFinding]:
    order = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: order.get(f.severity, len(order)))


def _overall_risk_label(severity_counts: dict[str, int], language: Language) -> str:
    labels = RISK_LABELS[language]
    if severity_counts.get(Severity.CRITICAL.value, 0) > 0:
        return labels["very_high"]
    if severity_counts.get(Severity.HIGH.value, 0) > 0:
        return labels["high"]
    if severity_counts.get(Severity.MEDIUM.value, 0) > 0:
        return labels["medium"]
    if severity_counts.get(Severity.LOW.value, 0) > 0:
        return labels["low"]
    return labels["none"]


class ReportFormatter:
    def format_report(
        self, report: AnalysisReport, audience: AudienceLevel, language: Language = "ar"
    ) -> FormattedReport:
        if audience == AudienceLevel.TECHNICAL:
            title, body = self._format_technical(report, language)
        elif audience == AudienceLevel.MANAGERIAL:
            title, body = self._format_managerial(report, language)
        else:
            title, body = self._format_non_technical(report, language)

        return FormattedReport(
            report_id=report.report_id,
            engine=report.engine,
            audience=audience,
            generated_at=report.generated_at,
            title=title,
            body_markdown=body,
            total_findings=report.total_findings,
            severity_counts=report.severity_counts,
        )

    # -- Technical: كل التفاصيل، بدون تبسيط ---------------------------------

    def _format_technical(self, report: AnalysisReport, language: Language) -> tuple[str, str]:
        if language == "en":
            title = "Full Technical Report"
            lines = [
                f"# {title}",
                "",
                f"**Target (network):** {report.target_network or '—'}  ",
                f"**Target (web):** {report.target_web or '—'}  ",
                f"**Total findings:** {report.total_findings}",
                "",
                "## Severity Summary",
                "",
            ]
        else:
            title = "التقرير التقني الكامل"
            lines = [
                f"# {title}",
                "",
                f"**الهدف (شبكة):** {report.target_network or '—'}  ",
                f"**الهدف (ويب):** {report.target_web or '—'}  ",
                f"**عدد النتائج الإجمالي:** {report.total_findings}",
                "",
                "## ملخّص حسب الخطورة",
                "",
            ]

        for sev in SEVERITY_ORDER:
            count = report.severity_counts.get(sev.value, 0)
            if count:
                lines.append(f"- **{sev.value}:** {count}")
        lines.append("")
        lines.append("## Executive Summary" if language == "en" else "## ملخّص عام")
        lines.append(report.executive_summary)
        lines.append("")
        lines.append("## Technical Findings" if language == "en" else "## تفاصيل النتائج (Technical Findings)")
        lines.append("")

        for finding in _sort_by_severity(report.findings):
            lines.append(f"### [{finding.severity.value}] {finding.title}")
            lines.append(f"- **Source module:** {finding.source_module}")
            if finding.affected_asset:
                lines.append(f"- **Affected asset:** {finding.affected_asset}")
            if finding.evidence:
                lines.append(f"- **Evidence:** `{finding.evidence}`")
            lines.append(f"- **Description:** {finding.description}")
            lines.append(f"- **Remediation:** {finding.remediation}")
            lines.append("")

        return title, "\n".join(lines)

    # -- Managerial: أولويات وتأثير على العمل، بدون تفاصيل تقنية -------------

    def _format_managerial(self, report: AnalysisReport, language: Language) -> tuple[str, str]:
        risk_label = _overall_risk_label(report.severity_counts, language)
        sorted_findings = _sort_by_severity(report.findings)
        priority_findings = [
            f for f in sorted_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ][:5]
        if not priority_findings:
            priority_findings = sorted_findings[:3]

        critical = report.severity_counts.get(Severity.CRITICAL.value, 0)
        high = report.severity_counts.get(Severity.HIGH.value, 0)
        medium = report.severity_counts.get(Severity.MEDIUM.value, 0)
        severity_labels = SEVERITY_LABELS[language]

        if language == "en":
            title = "Decision-Maker Summary Report"
            lines = [
                f"# {title}",
                "",
                f"**Overall risk level:** {risk_label}",
                f"**Total findings:** {report.total_findings}",
                "",
                "## Overview",
                report.executive_summary,
                "",
            ]
            if critical or high:
                lines.append(f"⚠️ There are **{critical + high} item(s)** requiring remediation within days at most.")
            if medium:
                lines.append(f"There are also **{medium} item(s)** of medium priority, recommended to schedule within weeks.")
            lines.append("")
            if priority_findings:
                lines.append("## Top items requiring decisions/resources")
                lines.append("")
                for finding in priority_findings:
                    impact = finding.business_impact or finding.description
                    lines.append(f"**{finding.title}** _({severity_labels.get(finding.severity, finding.severity.value)})_")
                    lines.append(f"- Potential business impact: {impact}")
                    lines.append("")
            lines.append("_For full technical details and precise remediation steps, refer to the technical report with your technical team._")
        else:
            title = "تقرير موجز لصاحب القرار"
            lines = [
                f"# {title}",
                "",
                f"**مستوى الخطورة العام:** {risk_label}",
                f"**إجمالي النقاط المكتشفة:** {report.total_findings}",
                "",
                "## الوضع العام",
                report.executive_summary,
                "",
            ]
            if critical or high:
                lines.append(f"⚠️ يوجد **{critical + high} نقطة** تحتاج معالجة خلال أيام قليلة كحد أقصى.")
            if medium:
                lines.append(f"يوجد أيضاً **{medium} نقطة** بأولوية متوسطة، يُنصح بجدولتها خلال أسابيع.")
            lines.append("")
            if priority_findings:
                lines.append("## أهم النقاط التي تحتاج قراراً/موارد")
                lines.append("")
                for finding in priority_findings:
                    impact = finding.business_impact or finding.description
                    lines.append(f"**{finding.title}** _({severity_labels.get(finding.severity, finding.severity.value)})_")
                    lines.append(f"- التأثير المحتمل على العمل: {impact}")
                    lines.append("")
            lines.append("_للتفاصيل التقنية الكاملة وخطوات الإصلاح الدقيقة، راجع التقرير التقني مع الفريق التقني._")

        return title, "\n".join(lines)

    # -- Non-technical: لغة يومية بسيطة، بدون أي مصطلحات تقنية --------------

    def _format_non_technical(self, report: AnalysisReport, language: Language) -> tuple[str, str]:
        sorted_findings = _sort_by_severity(report.findings)
        meaningful_findings = [f for f in sorted_findings if f.severity != Severity.INFO]

        title = "Simplified Report" if language == "en" else "تقرير مبسّط"
        lines = [f"# {title}", ""]

        if not meaningful_findings:
            lines.append(
                "The scan did not find any significant issues that need your concern right now. 👍"
                if language == "en"
                else "الفحص ما لقى أي مشكلة مهمة تستدعي قلقكم حالياً. 👍"
            )
            return title, "\n".join(lines)

        critical_or_high = [f for f in meaningful_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

        if language == "en":
            if critical_or_high:
                lines.append(
                    f"We scanned your site/system and found **{len(critical_or_high)} important issue(s)** "
                    f"that need attention soon, plus some less important notes."
                )
            else:
                lines.append(
                    "We scanned your site/system and found a few notes, mostly minor — no need for major "
                    "concern, but it's best to address them."
                )
            lines.append("")
            lines.append("## What did we find?")
            lines.append("")
            for finding in meaningful_findings:
                summary = finding.plain_summary or finding.description
                marker = "🔴" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
                lines.append(f"{marker} {summary}")
                lines.append("")
            lines.append("## What should you do?")
            lines.append("")
            lines.append(
                "Contact your technical team (or whoever is responsible for the site/system) and share "
                "this report along with the full technical report, so they can fix these items."
            )
            if critical_or_high:
                lines.append("Items marked 🔴 are more important and deserve faster action than items marked 🟡.")
        else:
            if critical_or_high:
                lines.append(
                    f"فحصنا موقعكم/نظامكم ولقينا **{len(critical_or_high)} مشكلة مهمة** "
                    f"تحتاج اهتمام قريب. بالإضافة لبعض الملاحظات الأقل أهمية."
                )
            else:
                lines.append(
                    "فحصنا موقعكم/نظامكم ولقينا بعض الملاحظات، معظمها بسيطة نسبياً — لا داعي للقلق الشديد، "
                    "لكن يُفضّل معالجتها."
                )
            lines.append("")
            lines.append("## شو لقينا؟")
            lines.append("")
            for finding in meaningful_findings:
                summary = finding.plain_summary or finding.description
                marker = "🔴" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "🟡"
                lines.append(f"{marker} {summary}")
                lines.append("")
            lines.append("## شو لازم تعملوا؟")
            lines.append("")
            lines.append(
                "تواصلوا مع فريقكم التقني (أو الشخص المسؤول عن الموقع/النظام) وشاركوهم هذا التقرير "
                "بالإضافة للتقرير التقني الكامل، عشان يقدروا يصلّحوا هالنقاط."
            )
            if critical_or_high:
                lines.append("النقاط المعلّمة 🔴 أهم وتستاهل معالجة أسرع من النقاط المعلّمة 🟡.")

        return title, "\n".join(lines)
