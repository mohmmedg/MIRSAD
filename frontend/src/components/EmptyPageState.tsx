import { useNavigate } from "react-router-dom";
import { ShieldHalf, ArrowRight, ArrowLeft } from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./EmptyPageState.module.css";

export function EmptyPageState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  const { language } = useLanguage();
  const navigate = useNavigate();
  const Arrow = language === "ar" ? ArrowLeft : ArrowRight;

  return (
    <section className={`${styles.wrap} animateIn`}>
      <div className={styles.orb}>
        <ShieldHalf size={40} strokeWidth={1.2} />
      </div>
      <h2>{title}</h2>
      <p>{description}</p>
      <button className={styles.cta} onClick={() => navigate("/scans")}>
        {language === "ar" ? "الذهاب إلى مركز الفحص" : "Go to scan workspace"}
        <Arrow size={15} />
      </button>
    </section>
  );
}
