import { useState } from "react";
import { Network, Play, Loader2 } from "lucide-react";
import { runNetworkScan, ApiError } from "../api/client";
import type { NetworkScanResult } from "../types/api";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";

interface Props { onResult: (result: NetworkScanResult) => void; }

export function NetworkScanControl({ onResult }: Props) {
  const { strings } = useLanguage(); const s = strings.network;
  const [target,setTarget]=useState("127.0.0.1");
  const [scanType,setScanType]=useState("quick");
  const [ports,setPorts]=useState("");
  const [timing,setTiming]=useState(4);
  const [state,setState]=useState<DotState>("idle"); const [error,setError]=useState<string|null>(null);
  async function handleRun(){ if(!target.trim())return; setState("running"); setError(null); try{ const r=await runNetworkScan(target.trim(),scanType,ports.trim()||undefined,timing); setState(r.status==="completed"?"completed":"failed"); if(r.status==="failed"&&r.error_message)setError(r.error_message); onResult(r);}catch(err){setState("failed");setError(err instanceof ApiError?err.message:"Unexpected error");}}
  return <div className={styles.card}>
    <div className={styles.sectionHeader}><span className={styles.sectionIcon}><Network size={14}/></span><span className={styles.sectionLabel}>{s.sectionLabel}</span></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.targetLabel}</label><input className={styles.input} value={target} onChange={e=>setTarget(e.target.value)} disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.scanTypeLabel}</label><select className={styles.select} value={scanType} onChange={e=>setScanType(e.target.value)} disabled={state==="running"}>
      <option value="discovery">{s.discoveryOption}</option><option value="quick">{s.quickOption}</option><option value="balanced">{s.balancedOption}</option><option value="comprehensive">{s.comprehensiveOption}</option><option value="udp">{s.udpOption}</option><option value="vulnerability">{s.vulnerabilityOption}</option><option value="deep">{s.deepOption}</option><option value="maximum">{s.maximumOption}</option>
    </select></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.portsLabel}</label><input className={styles.input} value={ports} onChange={e=>setPorts(e.target.value)} placeholder="22,80,443 أو T:1-65535,U:53,161" disabled={state==="running"}/><div className={styles.hint}>{s.portsHint}</div></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.timingLabel}: T{timing}</label><input type="range" min="0" max="5" value={timing} onChange={e=>setTiming(Number(e.target.value))} disabled={state==="running"}/></div>
    <button className={styles.button} onClick={handleRun} disabled={state==="running"||!target.trim()}>{state==="running"?<><Loader2 size={14} className="spin"/> {s.running}</>:<><Play size={14}/> {s.runButton}</>}</button>
    <div className={styles.statusRow}><StatusDot state={state}/><span>{state==="idle"&&s.idle}{state==="running"&&s.runningStatus}{state==="completed"&&s.completed}{state==="failed"&&s.failed}</span></div>
    {error&&<div className={styles.errorText}>{error}</div>}
  </div>;
}
