import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type {
  UnifiedScanResult,
  NetworkScanResult,
  WebScanResult,
  APISecurityResult,
  AnalysisReport,
  FormattedReport,
  CompareAnalysisResponse,
  AudienceLevel,
  Language,
} from "../types/api";
import type { EngineChoice } from "../components/AnalysisControl";
import {
  runAiAnalysis,
  runRuleBasedAnalysis,
  generateRuleBasedReport,
  compareAnalysis,
  getAttackSurfaceGraph,
  getScanHistoryRecords,
  getActiveJobs,
  getJob,
  type AttackSurfaceGraph,
  type JobSnapshot,
  type ScanHistoryRecord,
  ApiError,
} from "../api/client";
import { getTenantId } from "../auth/supabase";
import { useLanguage } from "../i18n/LanguageContext";
import { buildUnifiedFromPartial } from "../utils/buildUnifiedFromPartial";
import { clearCurrentScanSnapshot, loadCurrentScanSnapshot, saveCurrentScanSnapshot } from "../offline/db";
import { safeErrorMessage } from "../utils/security";
import {
  ACTIVE_SCAN_KEY, LAST_SCAN_KEY, SELECTED_SCAN_KEY, TERMINAL_JOB_STATUSES,
  readScanKey, removeScanKey, writeScanKey,
} from "../utils/scanTracking";

export type ResultState =
  | { kind: "empty" }
  | { kind: "structured"; report: AnalysisReport }
  | { kind: "formatted"; report: FormattedReport }
  | { kind: "compare"; data: CompareAnalysisResponse };

interface ScanContextValue {
  networkResult: NetworkScanResult | null;
  webResult: WebScanResult | null;
  apiResult: APISecurityResult | null;
  unified: UnifiedScanResult | null;
  activeScanId: string | null;
  hasAnyScan: boolean;
  setNetworkResult: (r: NetworkScanResult | null) => void;
  setWebResult: (r: WebScanResult | null) => void;
  setApiResult: (r: APISecurityResult | null) => void;
  setUnified: (r: UnifiedScanResult | null) => void;
  applyFullScanResult: (r: UnifiedScanResult) => void;
  /** Make `r` the scan the whole workspace works on. Pass `scanId` when `r.scan_id` may be missing. */
  selectScan: (r: UnifiedScanResult, scanId?: string) => void;
  /** Load a stored scan by id (history cache first, then the API) and select it. Resolves false if it has no result. */
  selectScanById: (scanId: string) => Promise<boolean>;
  clearCurrentScan: () => Promise<void>;
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  analysisRunning: boolean;
  analysisError: string | null;
  result: ResultState;
  handleGenerate: (engine: EngineChoice, audience: AudienceLevel) => Promise<void>;
  getCachedGraph: (scanId: string) => AttackSurfaceGraph | null;
  loadGraph: (scanId: string) => Promise<AttackSurfaceGraph>;
  cachedJobs: Record<string, JobSnapshot>;
  cacheJob: (job: JobSnapshot) => void;
  getCachedReport: (key: string) => FormattedReport | null;
  cacheReport: (key: string, report: FormattedReport) => void;
  getCachedScanHistory: (key: string) => { scans: ScanHistoryRecord[]; total: number } | null;
  loadScanHistory: (key: string, query: { limit: number; offset: number; q: string; status: string }) => Promise<{ scans: ScanHistoryRecord[]; total: number }>;
  invalidateScanHistory: () => void;
}

const ScanContext = createContext<ScanContextValue | null>(null);

// A tiny localStorage job cache is only a paint-optimization; it is never authoritative.
// Scan-progress page can paint the previous state instantly instead of an
// empty screen while the slow first network round-trip completes.
// `result` is stripped: it can be huge and is refetched from the server anyway.
const JOB_CACHE_KEY = "mirsad_job_cache_v1";
function loadJobCache(): Record<string, JobSnapshot> {
  try {
    const raw = localStorage.getItem(JOB_CACHE_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch { return {}; }
}
function saveJobCache(jobs: Record<string, JobSnapshot>) {
  try {
    const newest = Object.values(jobs)
      .sort((a, b) => Date.parse(b.created_at || "") - Date.parse(a.created_at || ""))
      .slice(0, 3);
    const out: Record<string, JobSnapshot> = {};
    for (const j of newest) out[j.job_id] = { ...j, result: null };
    localStorage.setItem(JOB_CACHE_KEY, JSON.stringify(out));
  } catch { /* storage full or unavailable: cache is best-effort */ }
}

export function ScanProvider({ children }: { children: ReactNode }) {
  const { language, strings } = useLanguage();
  const [networkResult, setNetworkResult] = useState<NetworkScanResult | null>(null);
  const [webResult, setWebResult] = useState<WebScanResult | null>(null);
  const [apiResult, setApiResult] = useState<APISecurityResult | null>(null);
  const [unifiedFromFullScan, setUnified] = useState<UnifiedScanResult | null>(null);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const persistPartialWorkspace = useCallback((n: NetworkScanResult | null, w: WebScanResult | null, a: APISecurityResult | null) => {
    const partial = buildUnifiedFromPartial(n, w, a);
    if (partial?.scan_id) void saveCurrentScanSnapshot(partial, partial.scan_id, getTenantId()).catch(() => undefined);
  }, []);
  const setNetwork = useCallback((r: NetworkScanResult | null) => { setNetworkResult(r); persistPartialWorkspace(r, webResult, apiResult); }, [persistPartialWorkspace, webResult, apiResult]);
  const setWeb = useCallback((r: WebScanResult | null) => { setWebResult(r); persistPartialWorkspace(networkResult, r, apiResult); }, [persistPartialWorkspace, networkResult, apiResult]);
  const setApi = useCallback((r: APISecurityResult | null) => { setApiResult(r); persistPartialWorkspace(networkResult, webResult, r); }, [persistPartialWorkspace, networkResult, webResult]);
  // فحص "Full Assessment" هو الوحيد الذي يُرجع UnifiedScanResult جاهزاً من الـ
  // backend (بالترابط الكامل بين المحركات). عند تشغيل فحص فردي (Web/Network/API)
  // فقط، نبني عرضاً مكافئاً محلياً من نتيجته حتى لا تبقى صفحات الأصول/سطح
  // الهجوم/الاكتشافات/المخاطر فارغة بلا سبب واضح للمستخدم.
  const unified = useMemo(
    () => unifiedFromFullScan ?? buildUnifiedFromPartial(networkResult, webResult, apiResult),
    [unifiedFromFullScan, networkResult, webResult, apiResult]
  );
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [result, setResult] = useState<ResultState>({ kind: "empty" });
  const [lastGenerated, setLastGenerated] = useState<{ engine: EngineChoice; audience: AudienceLevel } | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  // Route components unmount on navigation. Keep expensive scan-derived data in the
  // provider so returning to a page renders immediately instead of showing a
  // loading state and fetching the same snapshot again.
  const [graphCache, setGraphCache] = useState<Record<string, AttackSurfaceGraph>>({});
  const [cachedJobs, setCachedJobs] = useState<Record<string, JobSnapshot>>(loadJobCache);
  useEffect(() => { saveJobCache(cachedJobs); }, [cachedJobs]);

  const [reportCache, setReportCache] = useState<Record<string, FormattedReport>>({});
  // Page-level API caches live above the route tree, so unmounting a page does not
  // discard its last rendered data. Requests are deduplicated and revalidated in
  // the background instead of forcing a loading screen on every return.
  const [scanHistoryCache, setScanHistoryCache] = useState<Record<string, { scans: ScanHistoryRecord[]; total: number }>>({});
  const scanHistoryCacheRef = useRef<Record<string, { scans: ScanHistoryRecord[]; total: number }>>({});
  const scanHistoryRequests = useRef<Record<string, Promise<{ scans: ScanHistoryRecord[]; total: number }>>>({});

  const hasAnyScan = Boolean(unified || networkResult || webResult || apiResult);

  async function performGenerate(engine: EngineChoice, audience: AudienceLevel, lang: Language) {
    setAnalysisRunning(true);
    setAnalysisError(null);
    const bundle = {
      network_scan: networkResult ?? undefined,
      web_scan: webResult ?? undefined,
      api_scan: apiResult ?? undefined,
    };
    try {
      if (engine === "ai") {
        setResult({ kind: "structured", report: await runAiAnalysis(bundle, lang) });
      } else if (engine === "compare") {
        setResult({ kind: "compare", data: await compareAnalysis(bundle, lang) });
      } else if (audience === "technical") {
        setResult({ kind: "structured", report: await runRuleBasedAnalysis(bundle, lang) });
      } else {
        setResult({ kind: "formatted", report: await generateRuleBasedReport(bundle, audience, lang) });
      }
    } catch (err) {
      setAnalysisError(err instanceof ApiError ? safeErrorMessage(err.status) : strings.app.genericError);
    } finally {
      setAnalysisRunning(false);
    }
  }

  async function handleGenerate(engine: EngineChoice, audience: AudienceLevel) {
    setLastGenerated({ engine, audience });
    await performGenerate(engine, audience, language);
  }

  useEffect(() => {
    if (lastGenerated && hasAnyScan) performGenerate(lastGenerated.engine, lastGenerated.audience, language);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [language]);

  const applyFullScanResult = useCallback((r: UnifiedScanResult) => {
    setUnified(r);
    setActiveScanId(r.scan_id ?? null);
    setNetworkResult(r.network_scan ?? null);
    setWebResult(r.web_scan ?? null);
    setApiResult(r.api_scan ?? null);
    if (r.scan_id) {
      writeScanKey(SELECTED_SCAN_KEY, r.scan_id);
      void saveCurrentScanSnapshot(r, r.scan_id, getTenantId()).catch(() => { /* UI state remains usable */ });
    }
  }, []);

  const selectScan = useCallback((r: UnifiedScanResult, scanId?: string) => {
    // A stored result normally carries its own scan_id; when it does not, the history
    // row's id is authoritative. Without an id the page-scoping (DefectDojo, raw data,
    // execution log...) would silently fall back to "nothing selected".
    const withId = !r.scan_id && scanId ? { ...r, scan_id: scanId } : r;
    setResult({ kind: "empty" });
    setLastGenerated(null);
    setAnalysisError(null);
    applyFullScanResult(withId);
  }, [applyFullScanResult]);

  const getCachedGraph = useCallback((scanId: string) => graphCache[scanId] ?? null, [graphCache]);

  const loadGraph = useCallback(async (scanId: string) => {
    const cached = graphCache[scanId];
    if (cached) return cached;
    const graph = await getAttackSurfaceGraph(scanId);
    setGraphCache((prev) => ({ ...prev, [scanId]: graph }));
    return graph;
  }, [graphCache]);

  const cacheJob = useCallback((job: JobSnapshot) => {
    setCachedJobs((prev) => ({ ...prev, [job.job_id]: job }));
  }, []);

  const getCachedReport = useCallback((key: string) => reportCache[key] ?? null, [reportCache]);
  const cacheReport = useCallback((key: string, report: FormattedReport) => {
    setReportCache((prev) => ({ ...prev, [key]: report }));
  }, []);

  const getCachedScanHistory = useCallback((key: string) => scanHistoryCacheRef.current[key] ?? null, []);
  const loadScanHistory = useCallback(async (key: string, query: { limit: number; offset: number; q: string; status: string }) => {
    if (!scanHistoryRequests.current[key]) {
      scanHistoryRequests.current[key] = getScanHistoryRecords(query).then((response) => {
        const next = { scans: response.scans ?? [], total: response.total ?? 0 };
        scanHistoryCacheRef.current[key] = next;
        setScanHistoryCache((prev) => ({ ...prev, [key]: next }));
        return next;
      }).finally(() => { delete scanHistoryRequests.current[key]; });
    }
    return scanHistoryRequests.current[key];
  }, []);
  const invalidateScanHistory = useCallback(() => {
    scanHistoryCacheRef.current = {};
    setScanHistoryCache({});
  }, []);

  const clearCurrentScan = useCallback(async () => {
    setUnified(null);
    setActiveScanId(null);
    setNetworkResult(null);
    setWebResult(null);
    setApiResult(null);
    setSearchQuery("");
    setResult({ kind: "empty" });
    setLastGenerated(null);
    setAnalysisError(null);
    setGraphCache({});
    setCachedJobs({});
    removeScanKey(SELECTED_SCAN_KEY);
    removeScanKey(LAST_SCAN_KEY);
    setReportCache({});
    // Scan history is independent of the current-scan workspace. Keep its cache
    // across "New Scan" so returning to History is instant; the page revalidates
    // it in the background. Logout unmounts the provider and drops this memory cache.
    await clearCurrentScanSnapshot();
  }, []);

  const selectScanById = useCallback(async (scanId: string) => {
    let record: ScanHistoryRecord | null = null;
    for (const page of Object.values(scanHistoryCacheRef.current)) {
      const hit = page.scans.find((x) => x.scan_id === scanId && x.result);
      if (hit) { record = hit; break; }
    }
    if (!record) {
      const res = await getScanHistoryRecords({ limit: 50, offset: 0, q: scanId });
      record = (res.scans ?? []).find((x) => x.scan_id === scanId) ?? null;
    }
    if (!record?.result) return false;
    selectScan(record.result, record.scan_id);
    return true;
  }, [selectScan]);

  // The poller below must always call the latest versions of these callbacks and
  // read the latest selection without being torn down/recreated on every render.
  const liveRefs = useRef({ activeScanId: null as string | null, applyFullScanResult, cacheJob, invalidateScanHistory });
  liveRefs.current = { activeScanId, applyFullScanResult, cacheJob, invalidateScanHistory };

  // Keep a durable browser marker for any server-side scan that is still running, and
  // finish the job of bringing its result into the workspace even when the user is NOT
  // on the progress page. Before, only ScanProgressPage applied a finished scan; a scan
  // that completed while the user was on another page left every page empty and the
  // progress page claiming "no active scan".
  useEffect(() => {
    let stopped = false;
    let refreshInFlight = false;
    let emptyStreak = 0;

    const finalizeTracked = async (jobId: string) => {
      try {
        const job = await getJob(jobId);
        if (stopped) return;
        if (!TERMINAL_JOB_STATUSES.has(String(job.status))) {
          // The list said "nothing active" but the job is alive (e.g. cancel_requested
          // is not listed as active). Keep tracking it.
          writeScanKey(ACTIVE_SCAN_KEY, jobId);
          return;
        }
        liveRefs.current.cacheJob(job);
        liveRefs.current.invalidateScanHistory();
        const cur = liveRefs.current.activeScanId;
        // Never hijack a scan the user deliberately opened from history in the meantime.
        if ((job.status === "completed" || job.status === "partial") && job.result && (!cur || cur === jobId)) {
          liveRefs.current.applyFullScanResult(job.result as UnifiedScanResult);
        }
      } catch { /* job gone or backend busy: nothing to apply, the history page still has it */ }
    };

    const refresh = async () => {
      // Do not allow slow authentication/DB requests to pile up every 3s.
      if (stopped || refreshInFlight) return;
      refreshInFlight = true;
      try {
        const jobs = await getActiveJobs();
        if (stopped) return;
        const active = (jobs ?? []).find((j) => !TERMINAL_JOB_STATUSES.has(String(j.status)));
        if (active?.job_id) {
          emptyStreak = 0;
          writeScanKey(ACTIVE_SCAN_KEY, active.job_id);
          writeScanKey(LAST_SCAN_KEY, active.job_id);
          return;
        }
        const tracked = readScanKey(ACTIVE_SCAN_KEY);
        if (!tracked) return;
        // A single empty answer is not proof that the scan ended (DB hiccup, replica
        // lag right after job creation). Require two in a row before concluding.
        emptyStreak += 1;
        if (emptyStreak < 2) return;
        emptyStreak = 0;
        removeScanKey(ACTIVE_SCAN_KEY);
        writeScanKey(LAST_SCAN_KEY, tracked);
        await finalizeTracked(tracked);
      } catch { /* keep the marker: a failed request says nothing about the scan */ }
      finally { refreshInFlight = false; }
    };
    void refresh();
    const timer = window.setInterval(refresh, 5000);

    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (readScanKey(ACTIVE_SCAN_KEY)) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => {
      stopped = true;
      window.clearInterval(timer);
      window.removeEventListener("beforeunload", beforeUnload);
    };
  }, []);

  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Never resurrect a completed/old scan into the "current workspace".
        // A snapshot is hydrated only while the durable backend job is still
        // active. Scan History remains the source for completed scans.
        const activeJobId = readScanKey(ACTIVE_SCAN_KEY);
        if (!activeJobId) {
          await clearCurrentScanSnapshot();
          return;
        }
        try {
          const active = await getActiveJobs();
          const stillActive = active.some((j) =>
            j.job_id === activeJobId &&
            !["completed", "partial", "failed", "cancelled"].includes(String(j.status))
          );
          if (!stillActive) {
            // Do not resurrect the old snapshot, but keep the ACTIVE marker: the poller
            // confirms the end of that scan, applies its finished result to the workspace
            // and keeps it as the "last scan" (a scan that ended while the tab was closed
            // used to simply vanish here).
            await clearCurrentScanSnapshot();
            return;
          }
        } catch {
          // Never resurrect a possibly completed/old scan when active state cannot be verified.
          // The ACTIVE marker is kept: a failed request says nothing about the scan.
          await clearCurrentScanSnapshot();
          return;
        }
        const snapshot = await loadCurrentScanSnapshot(getTenantId());
        if (!cancelled && snapshot?.scanId === activeJobId && snapshot.data && typeof snapshot.data === "object") {
          applyFullScanResult(snapshot.data as UnifiedScanResult);
        }
      } finally {
        if (!cancelled) setHydrated(true);
      }
    })();
    return () => { cancelled = true; };
  }, [applyFullScanResult]);

  // After a full page reload the in-memory selection is gone. Restore the scan the user
  // had selected (opened from history / just finished) from the backend, which is
  // authoritative and tenant-scoped. Runs after first paint so it never delays the app.
  useEffect(() => {
    if (!hydrated) return;
    const id = readScanKey(SELECTED_SCAN_KEY);
    if (!id || liveRefs.current.activeScanId) return;
    let cancelled = false;
    selectScanById(id)
      .then((ok) => { if (!ok && !cancelled) removeScanKey(SELECTED_SCAN_KEY); })
      .catch(() => { /* offline/backend busy: keep the marker and try again next load */ });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hydrated]);

  const value = useMemo<ScanContextValue>(
    () => ({
      networkResult,
      webResult,
      apiResult,
      unified,
      activeScanId,
      hasAnyScan,
      setNetwork: setNetwork,
      setWeb: setWeb,
      setApi: setApi,
      setNetworkResult: setNetwork,
      setWebResult: setWeb,
      setApiResult: setApi,
      setUnified,
      applyFullScanResult,
      selectScan,
      selectScanById,
      clearCurrentScan,
      searchQuery,
      setSearchQuery,
      analysisRunning,
      analysisError,
      result,
      handleGenerate,
      getCachedGraph,
      loadGraph,
      cachedJobs,
      cacheJob,
      getCachedReport,
      cacheReport,
      getCachedScanHistory,
      loadScanHistory,
      invalidateScanHistory,
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [networkResult, webResult, apiResult, unified, activeScanId, hasAnyScan, setNetwork, setWeb, setApi, searchQuery, analysisRunning, analysisError, result, applyFullScanResult, selectScan, selectScanById, clearCurrentScan, hydrated, graphCache, getCachedGraph, loadGraph, cachedJobs, cacheJob, reportCache, getCachedReport, cacheReport, scanHistoryCache, getCachedScanHistory, loadScanHistory, invalidateScanHistory]
  );

  if (!hydrated) return null;
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used within ScanProvider");
  return ctx;
}
