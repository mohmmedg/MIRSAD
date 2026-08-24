import { useState } from "react";
import { Cpu, Bot, GitCompareArrows, Sparkles, Loader2 } from "lucide-react";
import type { AudienceLevel } from "../types/api";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";

export type EngineChoice = "ai" | "rule_based" | "compare";

interface Props {
  hasAnyScan: boolean;
  isRunning: boolean;
  onGenerate: (engine: EngineChoice, audience: AudienceLevel) => void;
}

export function AnalysisControl({ hasAnyScan, isRunning, onGenerate }: Props) {
  const { strings } = useLanguage();
  const s = strings.analysis;
  const [engine, setEngine] = useState<EngineChoice>("ai");
  const [audience, setAudience] = useState<AudienceLevel>("technical");

  const engineOptions: { value: EngineChoice; label: string; hint: string; icon: React.ReactNode }[] = [
    { value: "rule_based", label: s.ruleBasedLabel, hint: s.ruleBasedHint, icon: <Cpu size={15} /> },
    { value: "ai", label: s.aiLabel, hint: s.aiHint, icon: <Bot size={15} /> },
    { value: "compare", label: s.compareLabel, hint: s.compareHint, icon: <GitCompareArrows size={15} /> },
  ];

  const audienceLabels: Record<AudienceLevel, string> = {
    technical: s.audienceTechnical,
    managerial: s.audienceManagerial,
    non_technical: s.audienceNonTechnical,
  };

  return (
    <div className={styles.card}>
      <div className={styles.sectionHeader}>
        <span className={styles.sectionIcon}>
          <Sparkles size={14} strokeWidth={2.25} />
        </span>
        <span className={styles.sectionLabel}>{s.sectionLabel}</span>
      </div>

      <div className={styles.field}>
        <span className={styles.fieldLabel}>{s.engineLabel}</span>
        <div className={styles.radioGroup}>
          {engineOptions.map((opt) => (
            <label
              key={opt.value}
              className={`${styles.radioOption} ${engine === opt.value ? styles.radioOptionActive : ""}`}
            >
              <input type="radio" name="engine" checked={engine === opt.value} onChange={() => setEngine(opt.value)} />
              <span className={styles.radioIcon}>{opt.icon}</span>
              <span>
                {opt.label}
                <div className={styles.hint}>{opt.hint}</div>
              </span>
            </label>
          ))}
        </div>
      </div>

      {engine === "rule_based" && (
        <div className={styles.field}>
          <label className={styles.fieldLabel} htmlFor="audience">
            {s.audienceLabel}
          </label>
          <select
            id="audience"
            className={styles.select}
            value={audience}
            onChange={(e) => setAudience(e.target.value as AudienceLevel)}
          >
            {(Object.keys(audienceLabels) as AudienceLevel[]).map((level) => (
              <option key={level} value={level}>
                {audienceLabels[level]}
              </option>
            ))}
          </select>
        </div>
      )}

      <button
        className={styles.button}
        disabled={!hasAnyScan || isRunning}
        onClick={() => onGenerate(engine, audience)}
      >
        {isRunning ? (
          <>
            <Loader2 size={14} className="spin" /> {s.generating}
          </>
        ) : (
          <>
            <Sparkles size={14} /> {s.generateButton}
          </>
        )}
      </button>

      {!hasAnyScan && <div className={styles.hint}>{s.needScanHint}</div>}
    </div>
  );
}
