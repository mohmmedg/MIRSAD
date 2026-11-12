import { useState } from "react";
import { Globe, Play, Loader2 } from "lucide-react";
import { runFullScanAsync, ApiError } from "../api/client";
import type { UnifiedScanResult } from "../types/api";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";
import { INPUT_LIMITS, safeUserError, safeErrorMessage, validateTarget } from "../utils/security";

interface Props { onResult: (result: UnifiedScanResult) => void; }

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
  const [maxPages, setMaxPages] = useState("10000");
  const [maxDepth, setMaxDepth] = useState("32");
  const [state, setState] = useState<DotState>("idle");
  const [error, setError] = useState<string | null>(null);

  // يمر عبر /platform/scan/async (web فقط) بدل النسخة المتزامنة — نفس منطق
  // normalizer/correlator/risk_engine محفوظ، فقط عبر polling دوري بدل انتظار
  // طلب HTTP واحد قد يطول (لا مهلة من جهة المتصفح على fetch() مباشر).
  async function handleRun() {
    const checked = validateTarget(target, { maxLength: INPUT_LIMITS.webTarget, requireHttpUrl: true });
    const pages = Number(maxPages);
    const depth = Number(maxDepth);
    if (!checked.ok) { setState("failed"); setError(checked.message); return; }
    if (!Number.isInteger(pages) || pages < 5 || pages > INPUT_LIMITS.maxPages || !Number.isInteger(depth) || depth < 1 || depth > INPUT_LIMITS.maxDepth) {
      setState("failed"); setError("تحقق من حدود الصفحات والعمق."); return;
    }
    setState("running"); setError(null);
    try {
      const result = await runFullScanAsync({
        target: checked.value, network: false, web: true, api: false,
        // scan_profile:"custom" — بدونها resolve_profile() بالباك اند يفرض
        // قيم بروفايل "standard" على web_profile/max_pages/max_depth ويتجاهل
        // اختياراتك هنا بالكامل.
        scan_profile: "custom",
        web_profile: profile, max_pages: pages, max_depth: depth,
      });
      const web = result.web_scan;
      setState(web?.status === "completed" ? "completed" : "failed");
      if (web?.status === "failed" && web.error_message) setError(safeUserError(web.error_message, "فشل فحص الويب."));
      onResult(result);
    } catch (err) {
      setState("failed"); setError(err instanceof ApiError ? safeErrorMessage(err.status) : safeUserError(err, "تعذر تشغيل فحص الويب."));
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
        <input id="web-target" className={styles.input} value={target} onChange={(e) => setTarget(e.target.value)} maxLength={INPUT_LIMITS.webTarget} placeholder={s.placeholder} disabled={state === "running"} />
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
          <input className={styles.input} type="number" min="5" max="10000" value={maxPages} onChange={(e) => setMaxPages(e.target.value)} disabled={state === "running"} />
        </div>
        <div className={styles.field}>
          <label className={styles.fieldLabel}>Max depth</label>
          <input className={styles.input} type="number" min="1" max="32" value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} disabled={state === "running"} />
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
