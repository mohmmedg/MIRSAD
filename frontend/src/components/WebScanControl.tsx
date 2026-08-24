import { useState } from "react";
import { Globe, Play, Loader2 } from "lucide-react";
import { runWebScan, ApiError } from "../api/client";
import type { WebScanResult } from "../types/api";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";

interface Props { onResult: (result: WebScanResult) => void; }

const PROFILES = [
  ["quick", "Quick — discovery + passive checks"],
  ["balanced", "Balanced — crawler + templates + canaries"],
  ["deep", "Deep — larger crawl + broader checks"],
  ["maximum", "Maximum — widest bounded coverage"],
  ["passive", "Passive — no active canary payloads"],
];

export function WebScanControl({ onResult }: Props) {
  const { strings } = useLanguage();
  const s = strings.web;
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("balanced");
  const [maxPages, setMaxPages] = useState("60");
  const [maxDepth, setMaxDepth] = useState("3");
  const [state, setState] = useState<DotState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    if (!target.trim()) return;
    setState("running"); setError(null);
    try {
      const result = await runWebScan(target.trim(), profile, Number(maxPages), Number(maxDepth));
      setState(result.status === "completed" ? "completed" : "failed");
      if (result.status === "failed" && result.error_message) setError(result.error_message);
      onResult(result);
    } catch (err) {
      setState("failed"); setError(err instanceof ApiError ? err.message : "Unexpected error");
    }
  }

  return (
    <div className={styles.card}>
      <div className={styles.sectionHeader}>
        <span className={styles.sectionIcon}><Globe size={14} strokeWidth={2.25} /></span>
        <span className={styles.sectionLabel}>{s.sectionLabel}</span>
      </div>
      <div className={styles.field}>
        <label className={styles.fieldLabel} htmlFor="web-target">{s.targetLabel}</label>
        <input id="web-target" className={styles.input} value={target} onChange={(e) => setTarget(e.target.value)} placeholder={s.placeholder} disabled={state === "running"} />
      </div>
      <div className={styles.field}>
        <label className={styles.fieldLabel}>Scan profile</label>
        <select className={styles.input} value={profile} onChange={(e) => setProfile(e.target.value)} disabled={state === "running"}>
          {PROFILES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </div>
      <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:8}}>
        <div className={styles.field}>
          <label className={styles.fieldLabel}>Max pages</label>
          <input className={styles.input} type="number" min="5" max="150" value={maxPages} onChange={(e) => setMaxPages(e.target.value)} disabled={state === "running"} />
        </div>
        <div className={styles.field}>
          <label className={styles.fieldLabel}>Max depth</label>
          <input className={styles.input} type="number" min="1" max="5" value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} disabled={state === "running"} />
        </div>
      </div>
      <button className={styles.button} onClick={handleRun} disabled={state === "running" || !target.trim()}>
        {state === "running" ? <><Loader2 size={14} className="spin" /> {s.running}</> : <><Play size={14} /> {s.runButton}</>}
      </button>
      <div className={styles.statusRow}><StatusDot state={state} /><span>{state === "idle" && s.idle}{state === "running" && s.runningStatus}{state === "completed" && s.completed}{state === "failed" && s.failed}</span></div>
      {error && <div className={styles.errorText}>{error}</div>}
    </div>
  );
}
