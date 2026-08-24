import { useState } from "react";
import { ShieldAlert, AlertTriangle, AlertCircle, Info, ChevronDown, ChevronUp, Wrench } from "lucide-react";
import type { AnalyzedFinding, Severity } from "../types/api";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./FindingCard.module.css";

const SEVERITY_CLASS: Record<Severity, string> = {
  Critical: styles.critical,
  High: styles.high,
  Medium: styles.medium,
  Low: styles.low,
  Info: styles.info,
};

const SEVERITY_ICON: Record<Severity, React.ReactNode> = {
  Critical: <ShieldAlert size={14} />,
  High: <AlertTriangle size={14} />,
  Medium: <AlertCircle size={14} />,
  Low: <Info size={14} />,
  Info: <Info size={14} />,
};

export function FindingCard({ finding }: { finding: AnalyzedFinding }) {
  const { strings } = useLanguage();
  const r = strings.report;
  const [expanded, setExpanded] = useState(finding.severity === "Critical" || finding.severity === "High");
  const sevClass = SEVERITY_CLASS[finding.severity];

  return (
    <div className={`${styles.card} animateInStagger`}>
      <div className={`${styles.spine} ${sevClass}`} aria-hidden="true" />
      <div className={styles.body}>
        <div className={styles.headerRow}>
          <span className={`${styles.iconBadge} ${sevClass}`}>{SEVERITY_ICON[finding.severity]}</span>
          <div className={styles.titleGroup}>
            <div className={styles.headerTop}>
              <span className={`${styles.severityTag} ${sevClass}`}>{finding.severity}</span>
              <span className={styles.title}>{finding.title}</span>
            </div>
            {finding.affected_asset && (
              <div className={styles.meta}>
                <span className="ltr">{finding.affected_asset}</span> · {finding.source_module}
              </div>
            )}
            <div className={styles.description}>{finding.description}</div>

            <button
              className={styles.detailsToggle}
              onClick={() => setExpanded((v) => !v)}
              aria-expanded={expanded}
              aria-controls={`finding-detail-${finding.finding_id}`}
            >
              {expanded ? (
                <>
                  {r.hideDetails} <ChevronUp size={13} />
                </>
              ) : (
                <>
                  {r.showDetails} <ChevronDown size={13} />
                </>
              )}
            </button>

            {expanded && (
              <div id={`finding-detail-${finding.finding_id}`} className={`${styles.detailBlock} animateIn`}>
                {finding.evidence && (
                  <div>
                    <div className={styles.detailLabel}>{r.evidenceLabel}</div>
                    <div className={styles.evidence}>{finding.evidence}</div>
                  </div>
                )}
                <div>
                  <div className={styles.detailLabel}>{r.remediationLabel}</div>
                  <div className={styles.remediation}>
                    <Wrench size={13} />
                    <span>{finding.remediation}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
