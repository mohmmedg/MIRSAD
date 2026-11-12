import { Bot, CheckCircle2, Sparkles } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { StructuredReportView } from "../components/ReportView";
import { PageHeader } from "../components/PageHeader";
import styles from "../components/UnifiedDashboard.module.css";

export function AIPage() {
  const { language } = useLanguage();
  const { result } = useScan();

  return (
    <section className="animateIn">
      <PageHeader icon={Bot} eyebrow="AI INTELLIGENCE" title={language === "ar" ? "ذكاء Gemini" : "Gemini intelligence"} />

      <div className={styles.aiCard}>
        <div className={styles.aiIcon}>
          <Bot size={21} />
        </div>
        <div className={styles.aiBody}>
          <div className={styles.kicker}>
            <Sparkles size={12} /> AI INTELLIGENCE
          </div>
          <h3>
            {language === "ar"
              ? "Gemini كطبقة تحقق، وليس كمصدر للحقيقة"
              : "Gemini as a validation layer, not the source of truth"}
          </h3>
          <p>
            {language === "ar"
              ? "الأدلة، القواعد، والـ correlation تبقى الأساس. يمكن للـ AI تلخيص السبب، تقدير الثقة، واقتراح remediation دون تحويل المؤشر المحتمل إلى ثغرة مؤكدة."
              : "Evidence, rules and correlation remain authoritative. AI can explain, validate confidence and suggest remediation without turning a potential signal into a confirmed vulnerability."}
          </p>
          <div className={styles.aiChecks}>
            <span>
              <CheckCircle2 size={13} /> Evidence-first
            </span>
            <span>
              <CheckCircle2 size={13} /> Redaction-aware
            </span>
            <span>
              <CheckCircle2 size={13} /> Confidence-bound
            </span>
          </div>
        </div>
      </div>

      {result.kind === "structured" && (
        <div style={{ marginTop: 16 }}>
          <StructuredReportView report={result.report} />
        </div>
      )}
    </section>
  );
}
