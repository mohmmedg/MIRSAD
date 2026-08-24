import { Boxes, Code2, Globe, Lock, Network, Waypoints } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats } from "../utils/scanStats";
import { EmptyPageState } from "../components/EmptyPageState";
import styles from "../components/UnifiedDashboard.module.css";

export function AttackSurfacePage() {
  const { language } = useLanguage();
  const { unified } = useScan();
  const stats = useDerivedScanStats(unified);

  if (!unified) {
    return (
      <EmptyPageState
        title={language === "ar" ? "لا يوجد سطح هجوم بعد" : "No attack surface yet"}
        description={
          language === "ar"
            ? "شغّل فحصاً كاملاً لبناء خريطة سطح الهجوم من النطاق والخدمات ونقاط النهاية."
            : "Run a full scan to build the attack surface map from the domain, services and endpoints."
        }
      />
    );
  }

  return (
    <section className="animateIn">
      <header className={styles.dashboardHeader}>
        <div>
          <div className={styles.kicker}>
            <Waypoints size={13} /> {language === "ar" ? "سطح الهجوم" : "ATTACK SURFACE"}
          </div>
          <h2 className={styles.title}>{language === "ar" ? "اكتشافات مترابطة" : "Correlated discovery"}</h2>
          <p className={styles.subtitle}>
            <span className="ltr">{unified.target}</span>
          </p>
        </div>
      </header>

      <div className={styles.card}>
        <div className={styles.surface}>
          <div className={styles.surfaceNode}>
            <Globe size={18} />
            <b className="ltr">{unified.target}</b>
            <small>DOMAIN</small>
          </div>
          <div className={styles.surfaceLine} />
          <div className={styles.surfaceBranch}>
            <div className={styles.surfaceNode}>
              <Network size={16} />
              <b>{stats.dnsAddresses.length}</b>
              <small>IPs</small>
            </div>
            <div className={styles.surfaceNode}>
              <Lock size={16} />
              <b>{stats.services}</b>
              <small>SERVICES</small>
            </div>
            <div className={styles.surfaceNode}>
              <Code2 size={16} />
              <b>{stats.totalEndpoints}</b>
              <small>ENDPOINTS</small>
            </div>
            <div className={styles.surfaceNode}>
              <Boxes size={16} />
              <b>{unified.technologies.length}</b>
              <small>TECHNOLOGIES</small>
            </div>
          </div>
        </div>
      </div>

      {stats.dnsAddresses.length > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Network size={15} />
            <span>{language === "ar" ? "عناوين IP المكتشفة" : "Discovered IP addresses"}</span>
          </div>
          <div className={styles.chipCloud}>
            {stats.dnsAddresses.map((ip) => (
              <span key={ip} className={`${styles.chip} ${styles.ipChip} ltr`}>
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
