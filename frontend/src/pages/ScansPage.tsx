import { useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, CheckCircle2 } from "lucide-react";
import { ApiKeyControl } from "../components/ApiKeyControl";
import { FullScanControl } from "../components/FullScanControl";
import { NetworkScanControl } from "../components/NetworkScanControl";
import { WebScanControl } from "../components/WebScanControl";
import { APISecurityControl } from "../components/APISecurityControl";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./ScansPage.module.css";

export function ScansPage() {
  const { language } = useLanguage();
  const navigate = useNavigate();
  const { unified, hasAnyScan, applyFullScanResult, setNetworkResult, setWebResult, setApiResult } = useScan();
  const Arrow = language === "ar" ? ArrowLeft : ArrowRight;

  return (
    <section className={`${styles.wrap} animateIn`}>
      <div className={styles.header}>
        <div>
          <h2>{language === "ar" ? "مركز الفحص" : "Scan workspace"}</h2>
          <p>{language === "ar" ? "شغّل المحركات وراقب النتائج لحظياً" : "Run engines and inspect evidence live"}</p>
        </div>
        <span className={styles.liveBadge}>
          <i /> LIVE
        </span>
      </div>

      {unified && (
        <div className={styles.doneBanner}>
          <CheckCircle2 size={16} />
          <span>
            {language === "ar"
              ? `تم آخر فحص لـ ${unified.target} بنتيجة مخاطر ${Math.round(unified.risk_score)}/100.`
              : `Last scan of ${unified.target} finished with a risk score of ${Math.round(unified.risk_score)}/100.`}
          </span>
          <button onClick={() => navigate("/")}>
            {language === "ar" ? "عرض النظرة العامة" : "View overview"}
            <Arrow size={13} />
          </button>
        </div>
      )}

      <div className={styles.grid}>
        <ApiKeyControl />
        <FullScanControl onResult={applyFullScanResult} />
        <NetworkScanControl onResult={setNetworkResult} />
        <WebScanControl onResult={setWebResult} />
        <APISecurityControl onResult={setApiResult} />
      </div>

      {hasAnyScan && !unified && (
        <div className={styles.hint}>
          {language === "ar"
            ? "المحركات الفردية جاهزة — نتائجها ستُستخدم عند توليد التحليل من صفحة التقارير."
            : "Individual engine results are ready — they'll feed the analysis once generated from the Reports page."}
        </div>
      )}
    </section>
  );
}
