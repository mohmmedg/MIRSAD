import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Bot, Cpu, FileText, CheckCircle2 } from "lucide-react";
import type { AnalysisReport, FormattedReport } from "../types/api";
import { SeverityStats } from "./SeverityStats";
import { FindingCard } from "./FindingCard";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./ReportView.module.css";

/** تقرير خام (AI أو rule-based/technical) — findings مهيكلة، بطاقات قابلة للطي. */
export function StructuredReportView({ report }: { report: AnalysisReport }) {
  const { strings } = useLanguage();
  const r = strings.report;

  return (
    <div className="animateIn">
      <div className={styles.headerBlock}>
        <div className={styles.engineTagRow}>
          <span className={styles.engineTag}>
            {report.engine === "ai" ? <Bot size={12} /> : <Cpu size={12} />}
            {report.engine === "ai" ? "AI Analysis (Gemini)" : "Rule-Based Analysis"}
          </span>
          {report.model_used && <span className={`${styles.modelTag} ltr`}>{report.model_used}</span>}
        </div>
        <SeverityStats severityCounts={report.severity_counts} total={report.total_findings} />
        <div className={styles.summaryBlock}><div><div className={styles.summaryLabel}>Risk Score / Coverage</div><p className={styles.summaryText}>Risk score: {report.risk_score}/100 · {Object.keys(report.coverage || {}).length} module(s) covered</p></div></div>
      </div>

      <div className={styles.summaryBlock}>
        <FileText size={16} className={styles.summaryIcon} />
        <div>
          <div className={styles.summaryLabel}>{r.executiveSummary}</div>
          <p className={styles.summaryText}>{report.executive_summary}</p>
        </div>
      </div>

      {report.findings.length === 0 ? (
        <div className={styles.emptyState}>
          <CheckCircle2 size={32} />
          <span>{r.noFindings}</span>
        </div>
      ) : (
        <div>
          <div className={styles.findingsHeader}>
            {r.findings} ({report.findings.length})
          </div>
          {report.top_recommendations?.length > 0 && <div className={styles.summaryBlock}><div><div className={styles.summaryLabel}>Top Recommendations</div><ul>{report.top_recommendations.map((x,i)=><li key={i}>{x}</li>)}</ul></div></div>}

      {report.findings.map((finding, i) => (
            <div key={finding.finding_id} style={{ ["--stagger-index" as string]: i }}>
              <FindingCard finding={finding} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** تقرير مُنسَّق (managerial / non_technical من rule-based) — نص markdown كبطاقة مستند. */
export function MarkdownReportView({ report }: { report: FormattedReport }) {
  return (
    <div className="animateIn">
      <div className={styles.headerBlock}>
        <SeverityStats severityCounts={report.severity_counts} total={report.total_findings} />
      </div>
      <div className={styles.docCard}>
        <div className={`${styles.markdownBody} ${report.audience === "non_technical" ? styles.plainMode : ""}`}>
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{report.body_markdown}</ReactMarkdown>
        </div>
      </div>
    </div>
  );
}
