import { FileText, Download, Loader2, ShieldCheck, FlaskConical } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AnalysisControl } from "../components/AnalysisControl";
import { StructuredReportView, MarkdownReportView } from "../components/ReportView";
import { CompareView } from "../components/CompareView";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { EmptyPageState } from "../components/EmptyPageState";
import { asSeverity } from "../utils/scanStats";
import panelStyles from "../panelBottom.module.css";
import { PageHeader } from "../components/PageHeader";
import styles from "../components/UnifiedDashboard.module.css";
import pageStyles from "./ReportsPage.module.css";
import { safeErrorMessage } from "../utils/security";
import { downloadScanReport, generatePlatformReport, ApiError, type ReportFormat } from "../api/client";
import type { FormattedReport, Severity } from "../types/api";

const EXPORT_FORMATS: ReportFormat[] = ["pdf", "json", "csv", "html", "sarif"];
const BLOB_TYPE: Record<ReportFormat, string> = {
  pdf: "application/pdf",
  csv: "text/csv;charset=utf-8",
  html: "text/html;charset=utf-8",
  json: "application/json;charset=utf-8",
  sarif: "application/json;charset=utf-8",
};

export function ReportsPage() {
  const { language } = useLanguage();
  const { hasAnyScan, analysisRunning, analysisError, result, handleGenerate, unified, getCachedReport, cacheReport } = useScan();
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportAudience, setExportAudience] = useState<"technical" | "managerial" | "non_technical">("technical");
  const [canonical, setCanonical] = useState<FormattedReport | null>(null);
  const [canonicalError, setCanonicalError] = useState<string | null>(null);
  const [canonicalLoading, setCanonicalLoading] = useState(false);

  // مصدر الحقيقة الوحيد لأرقام هذه الصفحة هو unified.findings نفسه — أي نفس
  // القائمة التي تعرضها صفحتا Findings وRisk بالضبط. هذا يضمن أن severity_counts
  // وtotal_findings هنا لا يمكن أن يختلفا عمّا تراه في اللوحة، بغض النظر عن مصدر
  // نص الشرح (markdown) القادم من الـ backend.
  const { severityCounts, totalFindings } = useMemo(() => {
    const counts: Partial<Record<Severity, number>> = {};
    for (const f of unified?.findings ?? []) {
      const sev = asSeverity(f.severity);
      counts[sev] = (counts[sev] ?? 0) + 1;
    }
    return { severityCounts: counts, totalFindings: unified?.findings.length ?? 0 };
  }, [unified]);

  // التقرير "الرسمي" لهذا الفحص: يُطلَب من نفس المسار الذي يحفظ فيه الـ backend
  // نتيجة الفحص (history.save → UnifiedScanResult)، وليس من محرك تحليل مستقل.
  // بهذا يستحيل بنيوياً أن يختلف عدد الاكتشافات أو رقم الخطورة هنا عمّا تراه في
  // Findings/Risk — كلاهما يقرآن نفس unified.findings/unified.risk_score.
  useEffect(() => {
    if (!unified?.scan_id) {
      setCanonical(null);
      setCanonicalError(null);
      return;
    }
    let cancelled = false;
    const cacheKey = `${unified.scan_id}|${language}|${exportAudience}`;
    const cached = getCachedReport(cacheKey);
    if (cached) {
      setCanonical(cached);
      setCanonicalError(null);
      setCanonicalLoading(false);
      return () => { cancelled = true; };
    }
    setCanonicalLoading(true);
    setCanonicalError(null);
    generatePlatformReport(unified.scan_id, language, "markdown", exportAudience)
      .then((data) => {
        if (cancelled) return;
        const report: FormattedReport = {
          report_id: unified.scan_id,
          engine: "rule_based",
          audience: exportAudience,
          generated_at: unified.finished_at ?? unified.started_at,
          title: unified.target,
          body_markdown: typeof data.content === "string" ? data.content : JSON.stringify(data.content, null, 2),
          total_findings: totalFindings,
          severity_counts: severityCounts,
        };
        cacheReport(cacheKey, report);
        setCanonical(report);
      })
      .catch((err) => {
        if (cancelled) return;
        setCanonical(null);
        setCanonicalError(err instanceof ApiError ? safeErrorMessage(err.status) : (language === "ar" ? "تعذر توليد التقرير." : "Could not generate the report."));
      })
      .finally(() => {
        if (!cancelled) setCanonicalLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // severityCounts/totalFindings مشتقّتان من unified نفسه، لا حاجة لإدراجهما هنا
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unified?.scan_id, unified?.target, unified?.finished_at, unified?.started_at, language, exportAudience, getCachedReport, cacheReport]);

  return (
    <section className="animateIn">
      <PageHeader icon={FileText} eyebrow={language === "ar" ? "التقارير" : "REPORTS"} title={language === "ar" ? "مركز التقارير" : "Report center"} description="Executive · Technical · JSON · SARIF · HTML" />

      {!hasAnyScan ? (
        <EmptyPageState
          title={language === "ar" ? "لا توجد بيانات فحص للتحليل" : "No scan data to analyze"}
          description={
            language === "ar"
              ? "شغّل فحصاً واحداً على الأقل من مركز الفحص قبل توليد التقرير."
              : "Run at least one scan engine from the scan workspace before generating a report."
          }
        />
      ) : (
        <div className={pageStyles.wrap}>
          {unified?.scan_id && (
            <div className={pageStyles.exportBar} aria-label={language === "ar" ? "تصدير التقرير" : "Report export"}>
              <span>{language === "ar" ? "تنزيل التقرير" : "Download report"}</span>
              <select
                aria-label={language === "ar" ? "جمهور التقرير" : "Report audience"}
                value={exportAudience}
                onChange={(e) => setExportAudience(e.target.value as typeof exportAudience)}
                disabled={Boolean(exporting)}
              >
                <option value="technical">{language === "ar" ? "تقني" : "Technical"}</option>
                <option value="managerial">{language === "ar" ? "إداري" : "Managerial"}</option>
                <option value="non_technical">{language === "ar" ? "غير تقني" : "Non-technical"}</option>
              </select>
              {EXPORT_FORMATS.map((format) => (
                <button key={format} type="button" disabled={Boolean(exporting)}
                  onClick={async () => {
                    setExporting(format);
                    try {
                      const data = await downloadScanReport(unified.scan_id, format, language, exportAudience);
                      const value = data.content_base64
                        ? Uint8Array.from(atob(data.content_base64), (c) => c.charCodeAt(0))
                        : new TextEncoder().encode(typeof data.content === "string" ? data.content : JSON.stringify(data.content, null, 2));
                      const blob = new Blob([value], { type: BLOB_TYPE[format] });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `mirsad-${unified.scan_id}-${exportAudience}.${format === "sarif" ? "sarif.json" : format}`; a.click(); URL.revokeObjectURL(url);
                    } finally { setExporting(null); }
                  }}>
                  {exporting === format ? <Loader2 size={14} className="spin" /> : <Download size={14} />}
                  {format.toUpperCase()}
                </button>
              ))}
            </div>
          )}

          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <ShieldCheck size={15} />
              <span>{language === "ar" ? "التقرير الرسمي لهذا الفحص" : "This scan's official report"}</span>
            </div>
            <p className={styles.subtitle} style={{ margin: "0 0 12px" }}>
              {language === "ar"
                ? "نفس بيانات Findings/Risk بالضبط — مُولَّد من نفس النتيجة المحفوظة لهذا الفحص، وليس بإعادة تحليل مستقلة."
                : "Exactly the same data as Findings/Risk — generated from this scan's saved result, not a separate re-analysis."}
            </p>
            {!unified?.scan_id && (
              <div className={pageStyles.hint}>
                {language === "ar"
                  ? "لا يوجد رقم فحص محفوظ بعد لهذا الفحص (نتيجة محلية فقط)."
                  : "No saved scan_id for this scan yet (local-only result)."}
              </div>
            )}
            {canonicalLoading && (
              <div className={pageStyles.hint}><Loader2 size={14} className="spin" /> {language === "ar" ? "جاري التحميل..." : "Loading..."}</div>
            )}
            {canonicalError && <div className={panelStyles.analysisError}>{canonicalError}</div>}
            {canonical && !canonicalLoading && <MarkdownReportView report={canonical} />}
          </div>

          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <FlaskConical size={15} />
              <span>{language === "ar" ? "تحليل مقارن مستقل (AI مقابل القواعد)" : "Independent comparative analysis (AI vs rule-based)"}</span>
            </div>
            <p className={styles.subtitle} style={{ margin: "0 0 12px" }}>
              {language === "ar"
                ? "هذا القسم يشغّل محرك تحليل منفصل تماماً عن الأنبوب الذي يغذي Findings/Risk/Assets (له قواعده الخاصة ولا يمر بالـ Correlator). أرقامه لأغراض المقارنة والعرض التعليمي فقط، وقد تختلف عمداً عن التقرير الرسمي أعلاه وعن صفحات اللوحة."
                : "This section runs an analysis engine that is completely separate from the pipeline behind Findings/Risk/Assets (its own rule set, no Correlator pass). Its numbers are for comparison/demo purposes only and may intentionally differ from the official report above and from the dashboard pages."}
            </p>
            <AnalysisControl hasAnyScan={hasAnyScan} isRunning={analysisRunning} onGenerate={handleGenerate} />
            {analysisError && <div className={panelStyles.analysisError}>{analysisError}</div>}
            {result.kind === "empty" && (
              <div className={pageStyles.hint}>
                {language === "ar" ? "اختر محركاً وجمهوراً ثم ولّد التقرير." : "Choose an engine and audience, then generate the report."}
              </div>
            )}
            {result.kind === "structured" && <StructuredReportView report={result.report} />}
            {result.kind === "formatted" && <MarkdownReportView report={result.report} />}
            {result.kind === "compare" && <CompareView data={result.data} />}
          </div>
        </div>
      )}
    </section>
  );
}
