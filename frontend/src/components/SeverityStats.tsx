import type { Severity } from "../types/api";
import { SEVERITY_ORDER } from "../types/api";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./SeverityStats.module.css";

const SEV_CLASS: Record<Severity, string> = {
  Critical: styles.critical,
  High: styles.high,
  Medium: styles.medium,
  Low: styles.low,
  Info: styles.info,
};

const SEG_CLASS: Record<Severity, string> = {
  Critical: styles.segCritical,
  High: styles.segHigh,
  Medium: styles.segMedium,
  Low: styles.segLow,
  Info: styles.segInfo,
};

interface Props {
  severityCounts: Partial<Record<Severity, number>>;
  total: number;
}

/**
 * "التوقيع البصري" للداشبورد: 5 بطاقات إحصائية (كل قيمة فيها رقم حقيقي من
 * النتائج، مو placeholder)، تحتها شريط نسبي متناسب مع التوزيع الفعلي.
 * البنية نفسها تنقل معلومة (توزيع الخطورة)، مو زخرفة مضافة.
 */
export function SeverityStats({ severityCounts, total }: Props) {
  const { strings } = useLanguage();
  const r = strings.report;

  const sevLabel: Record<Severity, string> = {
    Critical: r.severityStatCritical,
    High: r.severityStatHigh,
    Medium: r.severityStatMedium,
    Low: r.severityStatLow,
    Info: r.severityStatInfo,
  };

  if (total === 0) {
    return <div className={styles.empty}>{r.noResultsYet}</div>;
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.grid} role="list" aria-label={r.findings}>
        {SEVERITY_ORDER.map((sev, i) => {
          const count = severityCounts[sev] ?? 0;
          return (
            <div
              key={sev}
              role="listitem"
              className={`${styles.statCard} ${SEV_CLASS[sev]} animateInStagger`}
              style={{ ["--stagger-index" as string]: i }}
              aria-label={`${sevLabel[sev]}: ${count}`}
            >
              <span className={`${styles.statCount} ltr`} aria-hidden="true">
                {count}
              </span>
              <span className={styles.statLabel} aria-hidden="true">
                {sevLabel[sev]}
              </span>
            </div>
          );
        })}
      </div>
      <div className={styles.bar} role="img" aria-label={`${r.findings}: ${total}`}>
        {SEVERITY_ORDER.map((sev) => {
          const count = severityCounts[sev] ?? 0;
          if (count === 0) return null;
          const widthPct = (count / total) * 100;
          return <div key={sev} className={`${styles.segment} ${SEG_CLASS[sev]}`} style={{ width: `${widthPct}%` }} />;
        })}
      </div>
    </div>
  );
}
