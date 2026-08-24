import { Boxes } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats } from "../utils/scanStats";
import { EmptyPageState } from "../components/EmptyPageState";
import styles from "../components/UnifiedDashboard.module.css";

export function AssetsPage() {
  const { language, strings } = useLanguage();
  const { unified } = useScan();
  const stats = useDerivedScanStats(unified);
  const m = strings.unified;

  if (!unified) {
    return (
      <EmptyPageState
        title={language === "ar" ? "لا توجد أصول بعد" : "No assets yet"}
        description={
          language === "ar"
            ? "شغّل فحصاً لاكتشاف التقنيات، عناوين IP، ونقاط نهاية JavaScript."
            : "Run a scan to discover technologies, IP addresses and JavaScript endpoints."
        }
      />
    );
  }

  return (
    <section className="animateIn">
      <header className={styles.dashboardHeader}>
        <div>
          <div className={styles.kicker}>
            <Boxes size={13} /> {language === "ar" ? "الأصول" : "ASSETS"}
          </div>
          <h2 className={styles.title}>{language === "ar" ? "الأصول والتقنيات" : "Assets & technology"}</h2>
          <p className={styles.subtitle}>
            <span className="ltr">{unified.target}</span>
          </p>
        </div>
      </header>

      <div className={styles.metricGrid}>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "إجمالي الأصول" : "Total assets"}</span>
          <strong className={styles.metricValue}>{unified.assets.length}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "التقنيات" : "Technologies"}</span>
          <strong className={styles.metricValue}>{unified.technologies.length}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "عناوين IP" : "IP addresses"}</span>
          <strong className={styles.metricValue}>{stats.dnsAddresses.length}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "نقاط نهاية JS" : "JS endpoints"}</span>
          <strong className={styles.metricValue}>{stats.jsEndpoints}</strong>
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Boxes size={15} />
          <span>{language === "ar" ? "التقنيات المكتشفة" : "Detected technologies"}</span>
        </div>
        <div className={styles.chipCloud}>
          {unified.technologies.length ? (
            unified.technologies.map((technology) => (
              <span key={technology} className={`${styles.chip} ltr`}>
                {technology}
              </span>
            ))
          ) : (
            <span className={styles.muted}>{m.noneLabel}</span>
          )}
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Boxes size={15} />
          <span>{language === "ar" ? "عناوين IP" : "IP addresses"}</span>
        </div>
        <div className={styles.chipCloud}>
          {stats.dnsAddresses.length ? (
            stats.dnsAddresses.map((ip) => (
              <span key={ip} className={`${styles.chip} ${styles.ipChip} ltr`}>
                {ip}
              </span>
            ))
          ) : (
            <span className={styles.muted}>{m.noneLabel}</span>
          )}
        </div>
      </div>
    </section>
  );
}
