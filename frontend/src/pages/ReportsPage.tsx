import { FileText } from "lucide-react";
import { AnalysisControl } from "../components/AnalysisControl";
import { StructuredReportView, MarkdownReportView } from "../components/ReportView";
import { CompareView } from "../components/CompareView";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { EmptyPageState } from "../components/EmptyPageState";
import panelStyles from "../panelBottom.module.css";
import styles from "../components/UnifiedDashboard.module.css";
import pageStyles from "./ReportsPage.module.css";

export function ReportsPage() {
  const { language } = useLanguage();
  const { hasAnyScan, analysisRunning, analysisError, result, handleGenerate } = useScan();

  return (
    <section className="animateIn">
      <header className={styles.dashboardHeader}>
        <div>
          <div className={styles.kicker}>
            <FileText size={13} /> {language === "ar" ? "التقارير" : "REPORTS"}
          </div>
          <h2 className={styles.title}>{language === "ar" ? "مركز التقارير" : "Report center"}</h2>
          <p className={styles.subtitle}>Executive · Technical · JSON · SARIF · HTML</p>
        </div>
      </header>

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
      )}
    </section>
  );
}
