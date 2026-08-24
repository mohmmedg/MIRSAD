import { useMemo } from "react";
import type { Severity, UnifiedScanResult } from "../types/api";
import { SEVERITY_ORDER } from "../types/api";

const SEV_SET = new Set<string>(SEVERITY_ORDER);

export function asSeverity(value: string): Severity {
  return SEV_SET.has(value) ? (value as Severity) : "Info";
}

export function useDerivedScanStats(scan: UnifiedScanResult | null, searchQuery = "") {
  return useMemo(() => {
    if (!scan) {
      return {
        severityCounts: {} as Partial<Record<Severity, number>>,
        dnsAddresses: [] as string[],
        jsEndpoints: 0,
        totalEndpoints: 0,
        services: 0,
        completedModules: 0,
        progress: 0,
        filteredFindings: [] as UnifiedScanResult["findings"],
        topFindings: [] as UnifiedScanResult["findings"],
      };
    }

    const severityCounts: Partial<Record<Severity, number>> = {};
    for (const finding of scan.findings) {
      const sev = asSeverity(finding.severity);
      severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
    }

    const dnsAddresses = Array.isArray(scan.dns?.addresses) ? (scan.dns.addresses as string[]) : [];
    const jsEndpoints = Array.isArray(scan.javascript_intelligence?.endpoints)
      ? scan.javascript_intelligence.endpoints.length
      : 0;

    const q = searchQuery.trim().toLowerCase();
    const filteredFindings = !q
      ? scan.findings
      : scan.findings.filter((finding) =>
          [finding.title, finding.affected_asset, finding.source_module, finding.severity, ...(finding.tags ?? [])].some(
            (value) => String(value ?? "").toLowerCase().includes(q)
          )
        );

    const topFindings = [...filteredFindings].sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0));

    const totalEndpoints = (scan.web_scan?.endpoints_count ?? 0) + (scan.api_scan?.endpoints?.length ?? 0);
    const services = scan.network_scan?.open_ports?.length ?? 0;
    const completedModules = [
      scan.network_scan?.status === "completed",
      scan.web_scan?.status === "completed",
      scan.api_scan?.status === "completed",
    ].filter(Boolean).length;
    const progress = scan.status === "completed" ? 100 : Math.round((completedModules / 3) * 80);

    return {
      severityCounts,
      dnsAddresses,
      jsEndpoints,
      totalEndpoints,
      services,
      completedModules,
      progress,
      filteredFindings,
      topFindings,
    };
  }, [scan, searchQuery]);
}
