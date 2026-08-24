import { KeyRound, Lock, ShieldAlert, ShieldCheck } from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "../components/UnifiedDashboard.module.css";

export function SecurityPage() {
  const { language } = useLanguage();

  return (
    <section className="animateIn">
      <header className={styles.dashboardHeader}>
        <div>
          <div className={styles.kicker}>
            <ShieldCheck size={13} /> SECURITY
          </div>
          <h2 className={styles.title}>{language === "ar" ? "الأمان والوصول" : "Security & access"}</h2>
        </div>
      </header>

      <div className={styles.securityStrip}>
        <ShieldAlert size={20} />
        <div>
          <b>Security Center</b>
          <span>JWT · RBAC · Tenant isolation · Audit</span>
        </div>
        <span className={styles.secureBadge}>SERVER-SIDE</span>
      </div>

      <div className={styles.twoCol}>
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <KeyRound size={15} />
            <span>{language === "ar" ? "المصادقة" : "Authentication"}</span>
          </div>
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12, lineHeight: 1.7 }}>
            {language === "ar"
              ? "مصادقة JWT مع صلاحيات قائمة على الأدوار (RBAC) وعزل كامل بين المستأجرين (tenants)، مطبّقة بالكامل من طرف الخادم."
              : "JWT authentication with role-based access control (RBAC) and full tenant isolation, enforced entirely server-side."}
          </p>
        </div>

        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Lock size={15} />
            <span>{language === "ar" ? "التدقيق" : "Audit trail"}</span>
          </div>
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12, lineHeight: 1.7 }}>
            {language === "ar"
              ? "سجل تدقيق يوثّق كل عملية حساسة داخل المنصة (من نفّذها، الهدف، والوقت)، قابل للاستعراض من لوحة الإدارة."
              : "An audit log records every sensitive operation on the platform (who, what, when), reviewable from the admin panel."}
          </p>
        </div>
      </div>
    </section>
  );
}
