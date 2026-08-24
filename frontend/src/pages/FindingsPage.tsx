import { useState } from "react";
import { Siren } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats, asSeverity } from "../utils/scanStats";
import { EmptyPageState } from "../components/EmptyPageState";
import { FindingDrawer } from "../components/FindingDrawer";
import type { Severity } from "../types/api";
import styles from "../components/UnifiedDashboard.module.css";

const SEV_CLASS: Record<Severity, string> = {
  Critical: styles.critical,
  High: styles.high,
  Medium: styles.medium,
  Low: styles.low,
  Info: styles.info,
};

export function FindingsPage() {
  const { language, strings } = useLanguage();
  const { unified, searchQuery, setSearchQuery } = useScan();
  const stats = useDerivedScanStats(unified, searchQuery);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  if (!unified) {
    return (
      <EmptyPageState
        title={language === "ar" ? "لا توجد اكتشافات بعد" : "No findings yet"}
        description={
          language === "ar"
            ? "شغّل فحصاً كاملاً ليتم عرض الاكتشافات مرتّبة حسب درجة الخطورة والثقة."
            : "Run a full scan to see findings ranked by risk and confidence."
        }
      />
    );
  }

  const selected = unified.findings.find((finding) => finding.finding_id === selectedId);

  return (
    <section className="animateIn">
      <header className={styles.dashboardHeader}>
        <div>
          <div className={styles.kicker}>
            <Siren size={13} /> {language === "ar" ? "الاكتشافات" : "FINDINGS"}
          </div>
          <h2 className={styles.title}>{strings.unified.prioritizedFindingsTitle}</h2>
          <p className={styles.subtitle}>
            <span className="ltr">{unified.target}</span>
          </p>
        </div>

        <input
          placeholder={language === "ar" ? "ابحث في الاكتشافات..." : "Search findings..."}
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          style={{
            background: "var(--bg-panel-raised)",
            border: "1px solid var(--line)",
            borderRadius: 10,
            padding: "9px 12px",
            color: "var(--text-primary)",
            fontSize: 12,
            minWidth: 220,
          }}
        />
      </header>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Siren size={15} />
          <span>{strings.unified.prioritizedFindingsTitle}</span>
          <span className={styles.cardMeta}>
            {searchQuery ? `${stats.filteredFindings.length} matches` : `${unified.findings.length} total`}
          </span>
        </div>

        {stats.topFindings.length === 0 ? (
          <div className={styles.emptyFindings}>{strings.report.noFindings}</div>
        ) : (
          <div className={styles.findingList}>
            {stats.topFindings.map((finding) => {
              const sev = asSeverity(finding.severity);
              return (
                <button
                  key={finding.finding_id}
                  className={styles.findingRow}
                  onClick={() => setSelectedId(finding.finding_id)}
                >
                  <span className={`${styles.findingSev} ${SEV_CLASS[sev]}`}>{finding.severity}</span>
                  <div className={styles.findingBody}>
                    <div className={styles.findingTitle}>{finding.title}</div>
                    {finding.affected_asset && (
                      <div className={`${styles.findingAsset} ltr`}>{finding.affected_asset}</div>
                    )}
                  </div>
                  <div className={styles.findingMeta}>
                    <span>RISK {finding.risk?.score ?? 0}</span>
                    <span>{((finding.confidence ?? 0) * 100).toFixed(0)}% confidence</span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {selected && <FindingDrawer finding={selected} onClose={() => setSelectedId(null)} />}
    </section>
  );
}
