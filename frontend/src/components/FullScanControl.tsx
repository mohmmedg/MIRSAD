import { useState } from "react";
import { Layers, Play, Loader2 } from "lucide-react";
import { runFullScan, ApiError } from "../api/client";
import type { UnifiedScanResult } from "../types/api";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";

interface Props { onResult: (result: UnifiedScanResult) => void; }

export function FullScanControl({ onResult }: Props) {
  const { strings } = useLanguage(); const s = strings.fullScan;
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("balanced");
  const [pages, setPages] = useState(80);
  const [depth, setDepth] = useState(4);
  const [state, setState] = useState<DotState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    if (!target.trim()) return;
    setState("running"); setError(null);
    try {
      const result = await runFullScan({
        target: target.trim(),
        network: true,
        web: true,
        api: true,
        network_profile: profile,
        web_profile: profile === "maximum" ? "maximum" : "deep",
        max_pages: pages,
        max_depth: depth,
        graphql_introspection: true,
        probe_write_methods: false,
      });
      setState("completed");
      onResult(result);
    } catch (err) {
      setState("failed");
      setError(err instanceof ApiError ? err.message : "Unexpected error");
    }
  }

  return <div className={styles.card}>
    <div className={styles.sectionHeader}><span className={styles.sectionIcon}><Layers size={14} /></span><span className={styles.sectionLabel}>{s.sectionLabel}</span></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.targetLabel}</label><input className={styles.input} value={target} onChange={e => setTarget(e.target.value)} placeholder={s.placeholder} disabled={state === "running"} /></div>
    <div className={styles.field}>
      <label className={styles.fieldLabel}>{s.profileLabel}</label>
      <select className={styles.select} value={profile} onChange={e => setProfile(e.target.value)} disabled={state === "running"}>
        <option value="quick">{s.quickOption}</option>
        <option value="balanced">{s.balancedOption}</option>
        <option value="comprehensive">{s.comprehensiveOption}</option>
        <option value="maximum">{s.maximumOption}</option>
      </select>
    </div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.pagesLabel}</label><input className={styles.input} type="number" min={1} max={150} value={pages} onChange={e => setPages(Number(e.target.value))} disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.depthLabel}</label><input className={styles.input} type="number" min={0} max={6} value={depth} onChange={e => setDepth(Number(e.target.value))} disabled={state === "running"} /></div>
    <div className={styles.hint}>{s.hint}</div>
    <button className={styles.button} onClick={handleRun} disabled={state === "running" || !target.trim()}>
      {state === "running" ? <><Loader2 size={14} className="spin" /> {s.running}</> : <><Play size={14} /> {s.runButton}</>}
    </button>
    <div className={styles.statusRow}><StatusDot state={state} /><span>{state === "idle" && s.idle}{state === "running" && s.runningStatus}{state === "completed" && s.completed}{state === "failed" && s.failed}</span></div>
    {error && <div className={styles.errorText}>{error}</div>}
  </div>;
}
