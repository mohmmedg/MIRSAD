import { ApiKeyControl } from "../components/ApiKeyControl";
import { FullScanControl } from "../components/FullScanControl";
import { NetworkScanControl } from "../components/NetworkScanControl";
import { WebScanControl } from "../components/WebScanControl";
import { APISecurityControl } from "../components/APISecurityControl";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { ScanSearch } from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import styles from "./ScansPage.module.css";

export function ScansPage() {
  const { language } = useLanguage();
  const { applyFullScanResult } = useScan();

  return (
    <section className={`${styles.wrap} animateIn`}>
      <PageHeader icon={ScanSearch} title={language === "ar" ? "مركز الفحص" : "Scan workspace"} description={language === "ar" ? "شغّل المحركات وراقب النتائج لحظياً" : "Run engines and inspect evidence live"} actions={<span className={styles.liveBadge}><i /> LIVE</span>} />



      <div className={styles.grid}>
        <ApiKeyControl />
        <FullScanControl />
        {/* الفحوصات الفردية أصبحت تُعيد UnifiedScanResult حقيقياً (عبر /platform/scan
            بوحدة واحدة مفعّلة) بدل نتيجة خام كانت تُفرَّغ محلياً بالواجهة — لذلك تُطبَّق
            الآن جميعها بنفس applyFullScanResult تماماً مثل الفحص الكامل. */}
        <NetworkScanControl onResult={applyFullScanResult} />
        <WebScanControl onResult={applyFullScanResult} />
        <APISecurityControl onResult={applyFullScanResult} />
      </div>

    </section>
  );
}
