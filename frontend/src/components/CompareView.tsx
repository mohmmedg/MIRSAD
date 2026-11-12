import { Bot, Cpu, AlertOctagon } from "lucide-react";
import type { CompareAnalysisResponse } from "../types/api";
import { StructuredReportView } from "./ReportView";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./CompareView.module.css";

export function CompareView({ data }: { data: CompareAnalysisResponse }) {
  const { strings } = useLanguage();
  const c = strings.compare;

  return (
    <div className={`${styles.grid} animateIn`}>
      <div className={styles.column}>
        <div className={styles.columnHeader}>
          <Bot size={16} /> {c.aiColumn}
        </div>
        {data.ai_report ? (
          <StructuredReportView report={data.ai_report} />
        ) : (
          <div className={styles.errorBox}>
            <AlertOctagon size={16} />
            <span>{data.ai_error ?? c.aiUnavailable}</span>
          </div>
        )}
      </div>
      <div className={styles.column}>
        <div className={styles.columnHeader}>
          <Cpu size={16} /> {c.ruleBasedColumn}
        </div>
        <StructuredReportView report={data.rule_based_report} />
      </div>
    </div>
  );
}
