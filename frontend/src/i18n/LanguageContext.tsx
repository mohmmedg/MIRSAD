// i18n/LanguageContext.tsx
//
// يدير حالة اللغة الحالية للموقع كامل (chrome + محتوى التقارير عبر الـ API).
// عند التبديل، يغيّر أيضاً dir بالـ <html> عشان التخطيط (RTL/LTR) ينعكس
// صح على كل الموقع، مو بس النصوص.

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { Language } from "../types/api";
import { getStrings, type Strings } from "./strings";

interface LanguageContextValue {
  language: Language;
  strings: Strings;
  dir: "rtl" | "ltr";
  toggleLanguage: () => void;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<Language>("ar");
  const dir = language === "ar" ? "rtl" : "ltr";

  useEffect(() => {
    document.documentElement.dir = dir;
    document.documentElement.lang = language;
  }, [dir, language]);

  function toggleLanguage() {
    setLanguage((prev) => (prev === "ar" ? "en" : "ar"));
  }

  return (
    <LanguageContext.Provider value={{ language, strings: getStrings(language), dir, toggleLanguage }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage(): LanguageContextValue {
  const ctx = useContext(LanguageContext);
  if (!ctx) {
    throw new Error("useLanguage must be used within a LanguageProvider");
  }
  return ctx;
}
