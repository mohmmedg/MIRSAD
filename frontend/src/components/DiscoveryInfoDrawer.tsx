import { createPortal } from "react-dom";
import { useEffect } from "react";
import { X, Search, Info, ExternalLink } from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./UnifiedDashboard.module.css";

export type DiscoveryInfo = {
  type: string;
  value: string;
  method: string;
  source: string;
  evidence?: string;
  explanation?: string;
  command?: string;
  exploitability?: string;
};

export function DiscoveryInfoDrawer({ item, onClose }: { item: DiscoveryInfo; onClose: () => void }) {
  const { language } = useLanguage();
  const ar = language === "ar";
  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { document.body.style.overflow = previousOverflow; window.removeEventListener("keydown", onKey); };
  }, [onClose]);
  const isHttpUrl = /^https?:\/\//i.test(item.value);
  return createPortal((
    <div className={styles.drawerBackdrop} onClick={onClose}>
      <aside className={styles.drawer} dir={ar ? "rtl" : "ltr"} onClick={(e) => e.stopPropagation()}>
        <button className={styles.closeButton} onClick={onClose} aria-label="Close"><X size={18} /></button>
        <div className={styles.kicker}><Search size={13} /> {ar ? "تفاصيل الاكتشاف" : "DISCOVERY DETAILS"}</div>
        <h3 className="ltr">{isHttpUrl ? <a href={item.value} target="_blank" rel="noopener noreferrer">{item.value} <ExternalLink size={13} /></a> : item.value}</h3>
        <div className={styles.drawerSection}>
          <label>{ar ? "نوع العنصر" : "Item type"}</label>
          <p>{item.type}</p>
        </div>
        <div className={styles.drawerSection}>
          <label>{ar ? "كيف تم اكتشافه؟" : "How was it discovered?"}</label>
          <p><b>{item.method}</b></p>
          {item.explanation && <p>{item.explanation}</p>}
        </div>
        <div className={styles.drawerSection}>
          <label>{ar ? "المصدر" : "Source"}</label>
          <p>{item.source}</p>
        </div>
        {item.command && (
          <div className={styles.drawerSection}>
            <label>{ar ? "التعليمة التي نُفذت فعلياً" : "Exact command executed"}</label>
            <pre className="ltr">{item.command}</pre>
          </div>
        )}
        {item.exploitability && (
          <div className={styles.drawerSection}>
            <label>{ar ? "إمكانية الاستغلال" : "Exploitability"}</label>
            <p>{item.exploitability}</p>
          </div>
        )}
        {item.evidence && (
          <div className={styles.drawerSection}>
            <label>{ar ? "الدليل الذي أنتج الاكتشاف" : "Discovery evidence"}</label>
            <pre>{item.evidence}</pre>
          </div>
        )}
        <div className={styles.drawerSection}>
          <Info size={14} />
          <p>{ar ? "هذه المعلومة تشرح مسار الاكتشاف فقط، ولا تعني بحد ذاتها وجود ثغرة." : "This explains the discovery path only; it does not by itself mean a vulnerability exists."}</p>
        </div>
      </aside>
    </div>
  ), document.body);
}
