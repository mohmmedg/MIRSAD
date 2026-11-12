import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Code2, GitBranch, List, Download } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";
import { getExecutionEvents, getJobExecutions, getScanHistoryRecords, getJob, getLiveScanResult, type ExecutionEvent, type ExecutionSummary, type ScanHistoryRecord } from "../api/client";
import { RawResultsPanel } from "../components/RawResultsPanel";

export function RawScanResultsPage() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const { language } = useLanguage();
  const { unified, activeScanId, selectScan } = useScan();
  const ar = language === "ar";
  const [scan, setScan] = useState<ScanHistoryRecord | null>(null);
  const [executions, setExecutions] = useState<ExecutionSummary[]>([]);
  const [selectedExecutionId, setSelectedExecutionId] = useState("");
  const [events, setEvents] = useState<ExecutionEvent[]>([]);
  const [liveResult, setLiveResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const effectiveId = scanId || activeScanId || unified?.scan_id || "";
  const localScan = useMemo<ScanHistoryRecord | null>(() => {
    if (!unified || (effectiveId && unified.scan_id !== effectiveId)) return null;
    return { scan_id: unified.scan_id || effectiveId, target: unified.target, status: unified.status || "completed", findings_count: unified.findings?.length ?? 0, result: unified, risk_score: unified.risk_score ?? null, created_at: unified.started_at ?? null, started_at: unified.started_at ?? null, finished_at: unified.finished_at ?? null, result_quality: null, scan_kind: "full" };
  }, [effectiveId, unified]);

  useEffect(() => {
    if (!effectiveId) { setScan(null); return; }
    let cancelled = false;
    setLoading(true); setError("");
    Promise.allSettled([
      localScan ? Promise.resolve(localScan) : getScanHistoryRecords({ limit: 200, offset: 0, q: effectiveId }).then((r) => r.scans.find((x) => x.scan_id === effectiveId) ?? null),
      getJobExecutions(effectiveId),
    ]).then(([scanResult, execResult]) => {
      if (cancelled) return;
      if (scanResult.status === "fulfilled" && scanResult.value) { setScan(scanResult.value); if (scanResult.value.result) selectScan(scanResult.value.result); }
      else setError(ar ? "لم يتم العثور على الفحص المحدد." : "Selected scan was not found.");
      if (execResult.status === "fulfilled") {
        setExecutions(execResult.value);
        setSelectedExecutionId((prev) => prev || execResult.value[0]?.execution_id || "");
      }
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [ar, effectiveId, localScan, selectScan]);

  useEffect(() => {
    if (!effectiveId || !selectedExecutionId) { setEvents([]); return; }
    let cancelled = false;
    getExecutionEvents(effectiveId, selectedExecutionId, 5000).then((v) => { if (!cancelled) setEvents(v); }).catch(() => { if (!cancelled) setEvents([]); });
    return () => { cancelled = true; };
  }, [effectiveId, selectedExecutionId]);

  useEffect(() => {
    if (!effectiveId) return;
    let stopped = false;
    let inFlight = false;
    let timer: number | undefined;
    let lastSequence = 0;
    const terminal = new Set(["completed", "partial", "failed", "cancelled"]);
    const refresh = async () => {
      if (stopped || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      let isTerminal = false;
      try {
        const [jr, lr] = await Promise.all([getJob(effectiveId), getLiveScanResult(effectiveId)]);
        if (stopped) return;
        if (lr && Object.keys(lr).length) setLiveResult(lr);
        if (jr.result) { const result = jr.result as any; setScan(prev => prev ? { ...prev, result } : prev); }
        if (selectedExecutionId) {
          const ev = await getExecutionEvents(effectiveId, selectedExecutionId, 5000, 0, lastSequence || undefined);
          if (!stopped) {
            setEvents(prev => lastSequence ? [...prev, ...ev] : ev);
            if (ev.length) lastSequence = Math.max(lastSequence, ...ev.map((x) => x.sequence));
          }
        }
        isTerminal = terminal.has(String(jr.status).toLowerCase());
      } catch {} finally {
        inFlight = false;
        if (isTerminal) {
          if (timer) window.clearTimeout(timer);
        } else if (!stopped && document.visibilityState === "visible") {
          timer = window.setTimeout(refresh, 5000);
        }
      }
    };
    const onVisible = () => { if (document.visibilityState === "visible") void refresh(); else if (timer) window.clearTimeout(timer); };
    document.addEventListener("visibilitychange", onVisible);
    void refresh();
    return () => { stopped = true; if (timer) window.clearTimeout(timer); document.removeEventListener("visibilitychange", onVisible); };
  }, [effectiveId, selectedExecutionId]);
  const downloadExecution = () => {
    const payload = { scan_id: effectiveId, execution: executions.find((e) => e.execution_id === selectedExecutionId) ?? null, events, result: scan?.result ?? null };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = `mirsad-${effectiveId}-${selectedExecutionId || "raw"}.json`; a.click(); URL.revokeObjectURL(url);
  };

  return <section className="animateIn">
    <header style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:18,marginBottom:18}}>
      <div><div style={{display:"flex",alignItems:"center",gap:7,color:"var(--accent-action)",font:"600 10px var(--font-mono)",letterSpacing:".12em"}}><Code2 size={14}/> RAW / ISOLATED</div><h2 style={{margin:"7px 0 5px",font:"700 28px var(--font-display)"}}>{ar ? "البيانات الخام" : "Raw scan data"}</h2><p style={{margin:0,color:"var(--text-muted)",fontSize:12}}>{ar ? "النتيجة الخام مع عزل كل عملية تنفيذ وأحداثها وأوامرها عن العمليات المتوازية." : "Raw persisted data with every parallel execution isolated from the others."}</p></div>
      <button onClick={() => navigate("/scan-history")} style={{display:"inline-flex",alignItems:"center",gap:7,padding:"9px 12px",border:"1px solid var(--line)",borderRadius:8,background:"var(--bg-panel-raised)",color:"var(--text-primary)"}}><ArrowLeft size={15}/>{ar ? "سجل الفحوصات" : "Scan history"}</button>
    </header>
    {error && <div style={{padding:12,border:"1px solid var(--sev-high)",borderRadius:9,color:"var(--sev-high)",background:"var(--sev-high-dim)",marginBottom:12}}>{error}</div>}
    {loading ? <div className="pageLoading" aria-busy="true"/> : scan ? <>
      <section style={{padding:14,border:"1px solid var(--line)",borderRadius:12,background:"var(--bg-panel)",marginBottom:14}}>
        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}><GitBranch size={15}/><b>{ar ? "العملية المعروضة" : "Selected execution"}</b></div>
        <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
          <select value={selectedExecutionId} onChange={(e) => setSelectedExecutionId(e.target.value)} style={{minWidth:300,padding:"10px 12px",border:"1px solid var(--line)",borderRadius:8,background:"var(--bg-panel-raised)",color:"var(--text-primary)"}}>
            {executions.length ? executions.map((e) => <option key={e.execution_id} value={e.execution_id}>#{e.attempt} · {e.execution_id.slice(0,16)} · {e.status} · {e.event_count} events</option>) : <option value="">{ar ? "السجل القديم — لا توجد عملية منفصلة" : "Legacy record — no isolated execution"}</option>}
          </select>
          {selectedExecutionId && <button onClick={downloadExecution} style={{display:"inline-flex",alignItems:"center",gap:6,padding:"9px 11px",border:"1px solid var(--line)",borderRadius:8,background:"var(--bg-panel-raised)",color:"var(--text-primary)"}}><Download size={14}/>{ar ? "تصدير العملية كاملة" : "Export execution"}</button>}
          <button onClick={() => navigate(`/scan-execution/${encodeURIComponent(effectiveId)}`)} style={{padding:"9px 11px",border:"1px solid var(--line)",borderRadius:8,background:"var(--bg-panel-raised)",color:"var(--text-primary)"}}><List size={14}/>{ar ? "فتح مساحة التنفيذ" : "Open execution workspace"}</button>
        </div>
      </section>
      <RawResultsPanel scan={scan ? {...scan, result: (scan.result ?? (liveResult ? {
        scan_id: effectiveId, target: scan.target, status: scan.status,
        network_scan: (liveResult as any).network_scan ?? null,
        web_scan: (liveResult as any).web_scan ?? null,
        api_scan: (liveResult as any).api_scan ?? null,
        external_scanners: (liveResult as any).external_scanners ?? null,
      } : null)) as any} : scan}/>
      {selectedExecutionId && <section style={{marginTop:14,padding:14,border:"1px solid var(--line)",borderRadius:12,background:"var(--bg-panel)"}}>
        <h3 style={{marginTop:0}}>{ar ? `أحداث العملية ${selectedExecutionId.slice(0,16)}` : `Events for execution ${selectedExecutionId.slice(0,16)}`}</h3>
        {events.length ? <div style={{display:"grid",gap:7}}>{events.map((e) => <div key={e.event_id} style={{display:"grid",gridTemplateColumns:"60px 150px minmax(0,1fr)",gap:10,padding:"9px 10px",border:"1px solid var(--line)",borderRadius:8,background:"var(--bg-panel-raised)"}}><b className="ltr">#{e.sequence}</b><span className="ltr">{e.event_type}</span><div><div className="ltr" style={{fontFamily:"var(--font-mono)",fontSize:10}}>{e.created_at}</div><div style={{fontSize:12}}>{e.message}</div>{Object.keys(e.payload ?? {}).length ? <pre className="ltr" style={{whiteSpace:"pre-wrap",margin:"5px 0 0",fontSize:10}}>{JSON.stringify(e.payload, null, 2)}</pre> : null}</div></div>)}</div> : <p style={{color:"var(--text-muted)"}}>{ar ? "لا توجد أحداث محفوظة." : "No events persisted."}</p>}
      </section>}
    </> : <div style={{padding:40,textAlign:"center",border:"1px dashed var(--line-strong)",borderRadius:12,color:"var(--text-muted)"}}>{ar ? "اختر فحصاً من سجل الفحوصات أولاً." : "Select a scan from Scan History first."}</div>}
  </section>;
}
