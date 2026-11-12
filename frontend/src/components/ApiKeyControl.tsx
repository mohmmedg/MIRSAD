import { useState } from "react";
import { KeyRound, Save } from "lucide-react";
import { getApiKey, setApiKey } from "../api/client";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";

export function ApiKeyControl() {
  const { language } = useLanguage();
  const [value, setValue] = useState(() => getApiKey());
  const [saved, setSaved] = useState(false);

  function handleSave() {
    setApiKey(value);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1800);
  }

  const ar = language === "ar";

  return (
    <div className={styles.card}>
      <div className={styles.sectionHeader}>
        <span className={styles.sectionIcon}>
          <KeyRound size={14} strokeWidth={2.25} />
        </span>
        <span className={styles.sectionLabel}>
          {ar ? "API Key" : "API Key"}
        </span>
      </div>

      <div className={styles.field}>
        <label className={styles.fieldLabel} htmlFor="scanner-api-key">
          {ar ? "مفتاح الـ Backend (X-API-Key)" : "Backend API Key (X-API-Key)"}
        </label>
        <input
          id="scanner-api-key"
          className={styles.input}
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={ar ? "أدخل API Key الخاص بالتطبيق" : "Enter your application API key"}
          autoComplete="off"
        />
      </div>

      <button className={styles.button} onClick={handleSave}>
        <Save size={14} />
        {saved ? (ar ? "تم الحفظ" : "Saved") : (ar ? "حفظ المفتاح" : "Save API Key")}
      </button>
    </div>
  );
}
