import { Activity, AlertTriangle, ChartNoAxesCombined } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats } from "../utils/scanStats";
import { EmptyPageState } from "../components/EmptyPageState";
import { SeverityStats } from "../components/SeverityStats";
import { SEVERITY_ORDER, type Severity } from "../types/api";
import styles from "../components/UnifiedDashboard.module.css";

const SEV_CLASS: Record<Severity, string> = {
  Critical: styles.critical,
  High: styles.high,
  Medium: styles.medium,
  Low: styles.low,
  Info: styles.info,
};

export function RiskPage() {
  const { language, strings } = useLanguage();
  const { unified } = useScan();
  const stats = useDerivedScanStats(unified);

  if (!unified) {
    return (
      <EmptyPageState
        title={language === "ar" ? "لا توجد بيانات مخاطر بعد" : "No risk data yet"}
        description={
          language === "ar"
            ? "شغّل فحصاً كاملاً لحساب درجة المخاطر وتوزيع الخطورة عبر الاكتشافات."
            : "Run a full scan to compute the risk score and severity distribution across findings."
        }
      />
    );
  }

  return (
    <section className="animateIn">
      <header className={styles.dashboardHeader}>
        <div>
          <div className={styles.kicker}>
            <ChartNoAxesCombined size={13} /> {language === "ar" ? "المخاطر" : "RISK"}
          </div>
          <h2 className={styles.title}>{language === "ar" ? "توزيع المخاطر" : "Risk distribution"}</h2>
          <p className={styles.subtitle}>
            <span className="ltr">{unified.target}</span> · risk {Math.round(unified.risk_score)}/100
          </p>
        </div>
      </header>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Activity size={15} />
          <span>{language === "ar" ? "حسب درجة الخطورة" : "By severity"}</span>
          <span className={styles.cardMeta}>{unified.findings.length} findings</span>
        </div>
        <div className={styles.riskBars}>
          {SEVERITY_ORDER.map((sev) => {
            const count = stats.severityCounts[sev] ?? 0;
            const pct = unified.findings.length ? Math.max(3, (count / unified.findings.length) * 100) : 3;
            return (
              <div className={styles.riskBarRow} key={sev}>
                <span className={`${styles.sevDot} ${SEV_CLASS[sev]}`} />
                <span>{sev}</span>
                <div className={styles.barTrack}>
                  <div className={`${styles.barFill} ${SEV_CLASS[sev]}`} style={{ width: `${pct}%` }} />
                </div>
                <b>{count}</b>
              </div>
            );
          })}
        </div>
      </div>

      <SeverityStats severityCounts={stats.severityCounts} total={unified.findings.length} />

      {unified.warnings.length > 0 && (
        <div className={`${styles.card} ${styles.warningsCard}`}>
          <div className={styles.cardHeader}>
            <AlertTriangle size={15} />
            <span>{strings.unified.warningsTitle}</span>
          </div>
          <ul className={styles.warningsList}>
            {unified.warnings.map((warning, index) => (
              <li key={index}>{warning}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
