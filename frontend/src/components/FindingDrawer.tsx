import { X } from "lucide-react";
import type { UnifiedScanResult } from "../types/api";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./UnifiedDashboard.module.css";

type Finding = UnifiedScanResult["findings"][number];

export function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const { language } = useLanguage();

  return (
    <div className={styles.drawerBackdrop} onClick={onClose}>
      <aside
        className={styles.drawer}
        dir={language === "ar" ? "rtl" : "ltr"}
        onClick={(event) => event.stopPropagation()}
      >
        <button className={styles.closeButton} onClick={onClose} aria-label="Close">
          <X size={18} />
        </button>

        <div className={styles.kicker}>
          {finding.severity} · {finding.source_module}
        </div>

        <h3>{finding.title}</h3>

        <span className={`${styles.drawerAsset} ltr`}>{finding.affected_asset ?? "—"}</span>

        <div className={styles.drawerStats}>
          <span>
            Risk <b>{finding.risk?.score ?? 0}</b>
          </span>
          <span>
            Confidence <b>{Math.round((finding.confidence ?? 0) * 100)}%</b>
          </span>
        </div>

        <div className={styles.drawerSection}>
          <label>{language === "ar" ? "الوصف" : "Description"}</label>
          <p>{finding.description}</p>
        </div>

        <div className={styles.drawerSection}>
          <label>{language === "ar" ? "الأدلة" : "Evidence"}</label>
          <div className={styles.evidence}>
            {finding.evidence?.map((evidence) => (
              <div key={`${evidence.source}-${evidence.asset}`}>
                <b>{evidence.source}</b>
                <pre>{evidence.evidence}</pre>
              </div>
            ))}
          </div>
        </div>

        <div className={styles.drawerSection}>
          <label>{language === "ar" ? "المعالجة" : "Remediation"}</label>
          <p>{finding.remediation || "—"}</p>
        </div>

        {finding.tags?.length ? (
          <div className={styles.chipCloud}>
            {finding.tags.map((tag) => (
              <span key={tag} className={styles.chip}>
                {tag}
              </span>
            ))}
          </div>
        ) : null}
      </aside>
    </div>
  );
}
