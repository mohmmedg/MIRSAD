import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
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
  ApiError,
} from "../api/client";
import { useLanguage } from "../i18n/LanguageContext";
import { buildUnifiedFromPartial } from "../utils/buildUnifiedFromPartial";

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
  hasAnyScan: boolean;
  setNetworkResult: (r: NetworkScanResult | null) => void;
  setWebResult: (r: WebScanResult | null) => void;
  setApiResult: (r: APISecurityResult | null) => void;
  setUnified: (r: UnifiedScanResult | null) => void;
  applyFullScanResult: (r: UnifiedScanResult) => void;
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  analysisRunning: boolean;
  analysisError: string | null;
  result: ResultState;
  handleGenerate: (engine: EngineChoice, audience: AudienceLevel) => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const { language, strings } = useLanguage();
  const [networkResult, setNetworkResult] = useState<NetworkScanResult | null>(null);
  const [webResult, setWebResult] = useState<WebScanResult | null>(null);
  const [apiResult, setApiResult] = useState<APISecurityResult | null>(null);
  const [unifiedFromFullScan, setUnified] = useState<UnifiedScanResult | null>(null);
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

  const hasAnyScan = Boolean(networkResult || webResult || apiResult);

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
      setAnalysisError(err instanceof ApiError ? err.message : strings.app.genericError);
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

  function applyFullScanResult(r: UnifiedScanResult) {
    setUnified(r);
    setNetworkResult(r.network_scan ?? null);
    setWebResult(r.web_scan ?? null);
    setApiResult(r.api_scan ?? null);
  }

  const value = useMemo<ScanContextValue>(
    () => ({
      networkResult,
      webResult,
      apiResult,
      unified,
      hasAnyScan,
      setNetworkResult,
      setWebResult,
      setApiResult,
      setUnified,
      applyFullScanResult,
      searchQuery,
      setSearchQuery,
      analysisRunning,
      analysisError,
      result,
      handleGenerate,
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [networkResult, webResult, apiResult, unified, hasAnyScan, searchQuery, analysisRunning, analysisError, result]
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used within ScanProvider");
  return ctx;
}
