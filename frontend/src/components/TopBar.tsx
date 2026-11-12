import { useEffect, useRef, useState } from "react";
import { Languages, Loader2, Search, Wifi, WifiOff, Sun, Moon } from "lucide-react";
import { StatusDot } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import { MirsadMark } from "./MirsadMark";
import styles from "./TopBar.module.css";
import { useTheme } from "../context/ThemeContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

export function TopBar({ searchQuery = "", onSearch }: { searchQuery?: string; onSearch?: (value: string) => void }) {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const { strings, language, toggleLanguage } = useLanguage();
  const { theme, toggleTheme } = useTheme();
  const searchInputRef = useRef<HTMLInputElement>(null);

  // اختصار ⌘K/Ctrl+K كان مجرد تلميح بصري بلا تنفيذ فعلي — هذا يجعله يعمل حقاً.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function checkHealth() {
      try {
        const res = await fetch(`${API_BASE_URL}/health`);
        if (!cancelled) setBackendOnline(res.ok);
      } catch {
        if (!cancelled) setBackendOnline(false);
      }
    }
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  return (
    <header className={styles.topBar}>
      <div className={styles.mobileBrand}>
        <span className={styles.logoIcon}><MirsadMark size={54} /></span>
        <div className={styles.wordmark}>
          <span>{strings.topBar.title}</span>
          <span className={styles.wordmarkSub}>{strings.topBar.subtitle}</span>
        </div>
      </div>

      <div className={styles.searchBox}>
        <Search size={15} />
        <input
          ref={searchInputRef}
          value={searchQuery}
          onChange={(e) => onSearch?.(e.target.value)}
          placeholder={language === "ar" ? "ابحث في الأصول والاكتشافات وCVE..." : "Search assets, findings, CVEs..."}
          aria-label="Global search"
        />
        <kbd>⌘ K</kbd>
      </div>

      <div className={styles.actions}>
        <div className={styles.statusBadge} role="status" aria-live="polite">
          {backendOnline === null ? <Loader2 size={14} className="spin" /> : backendOnline ? <Wifi size={14} /> : <WifiOff size={14} />}
          <StatusDot state={backendOnline === null ? "idle" : backendOnline ? "completed" : "failed"} />
          <span className="ltr">{backendOnline === null ? strings.topBar.checking : backendOnline ? strings.topBar.online : strings.topBar.offline}</span>
        </div>
        <button className={styles.langButton} onClick={toggleTheme} aria-label="Toggle theme" title={theme === "dark" ? "Light mode" : "Dark mode"}>
          {theme === "dark" ? <Sun size={14}/> : <Moon size={14}/>}<span>{theme === "dark" ? "Light" : "Dark"}</span>
        </button>
        <button className={styles.langButton} onClick={toggleLanguage} aria-label="Toggle language" title={strings.topBar.langToggle}>
          <Languages size={14} /><span className="ltr">{language === "ar" ? "EN" : "AR"}</span>
        </button>
      </div>
    </header>
  );
}
