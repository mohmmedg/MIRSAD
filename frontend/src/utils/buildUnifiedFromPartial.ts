import type { NetworkScanResult, WebScanResult, APISecurityResult, UnifiedScanResult } from "../types/api";

/**
 * Individual module results are intentionally not converted into synthetic findings.
 * Severity/risk/finding identity belong to the backend deterministic pipeline.
 * This adapter only exposes real module outputs and honest coverage state.
 */
export function buildUnifiedFromPartial(
  network: NetworkScanResult | null,
  web: WebScanResult | null,
  api: APISecurityResult | null
): UnifiedScanResult | null {
  if (!network && !web && !api) return null;

  const target = web?.target ?? api?.target ?? network?.target ?? "";
  const startedAt = web?.started_at ?? api?.started_at ?? network?.started_at ?? new Date().toISOString();
  const finishedAt = web?.finished_at ?? api?.finished_at ?? network?.finished_at ?? undefined;
  const states = {
    network: network ? String(network.status).toUpperCase() : "NOT_TESTED",
    web: web ? String(web.status).toUpperCase() : "NOT_TESTED",
    api: api ? String(api.status).toUpperCase() : "NOT_TESTED",
  };
  const values = Object.values(states);
  const tested = values.filter((v) => v === "COMPLETED").length;
  const denominator = values.length;
  const coverage = {
    capabilities: states,
    tested,
    partial: values.filter((v) => v === "PARTIAL").length,
    not_tested: values.filter((v) => v === "NOT_TESTED").length,
    not_configured: 0,
    failed: values.filter((v) => v === "FAILED").length,
    numerator: tested,
    denominator,
    percentage: denominator ? Math.round((tested / denominator) * 100) : 0,
    network: network?.coverage ?? {},
    // WebScanResult has no per-module coverage field in the backend contract;
    // web coverage is represented only at the states/capabilities level above.
    api: api?.coverage ?? {},
    technologies: [],
    assets: 0,
  };

  return {
    scan_id: web?.scan_id ?? api?.scan_id ?? network?.scan_id ?? "",
    target,
    status: values.includes("FAILED") ? "partial" : "completed",
    started_at: startedAt,
    finished_at: finishedAt,
    network_scan: network ?? undefined,
    web_scan: web ?? undefined,
    api_scan: api ?? undefined,
    findings: [],
    coverage,
    risk_score: 0,
    technologies: [],
    assets: [],
    warnings: [
      "Individual module results are shown without synthetic findings. Run a full assessment for correlated findings, verification and deterministic risk."
    ],
    dns: {},
    subdomains: [],
    tls: {},
    javascript_intelligence: {},
    ai_validation: {},
    pipeline: { states },
    snapshot_version: "1",
    scanner_version: "1.0",
    ruleset_version: "1.0",
    risk_engine_version: "2.0",
  };
}
