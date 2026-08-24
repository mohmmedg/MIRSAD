import type { NetworkScanResult, WebScanResult, APISecurityResult, UnifiedScanResult } from "../types/api";

const CRITICAL_HINTS = ["sqli", "sql_injection", "rce", "command_injection", "auth_bypass", "idor", "ssrf"];
const HIGH_HINTS = ["xss", "path_traversal", "lfi", "csrf", "broken_auth", "injection"];

function severityForCheck(name: string): string {
  const n = name.toLowerCase();
  if (CRITICAL_HINTS.some((h) => n.includes(h))) return "Critical";
  if (HIGH_HINTS.some((h) => n.includes(h))) return "High";
  return "Medium";
}

const RISK_BY_SEVERITY: Record<string, number> = {
  Critical: 92,
  High: 72,
  Medium: 48,
  Low: 25,
  Info: 10,
};

/**
 * لا يوجد endpoint خلفي يُرجع UnifiedScanResult إلا من فحص "Full Assessment"
 * الذي يشغّل الثلاث محركات معاً. عند تشغيل فحص فردي (Web/Network/API) فقط،
 * تبقى صفحات الأصول/سطح الهجوم/الاكتشافات/المخاطر فارغة لأنها تعتمد حصراً
 * على unified. هذه الدالة تبني عرضاً مكافئاً من أي نتائج فردية متوفرة حتى
 * تظهر بيانات حقيقية دون انتظار فحص شامل.
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

  const findings: UnifiedScanResult["findings"] = [];

  (web?.vulnerability_checks ?? [])
    .filter((c) => c.vulnerable)
    .forEach((c, i) => {
      const severity = severityForCheck(c.check_name);
      findings.push({
        finding_id: `web-vuln-${i}-${c.check_name}`,
        source_module: "web_scan",
        title: c.check_name,
        severity,
        confidence: Number(c.confidence) || 0.7,
        description: c.evidence ?? "",
        evidence: c.evidence ? [{ source: "web_scan", asset: c.url ?? target, evidence: c.evidence }] : [],
        affected_asset: c.url ?? target,
        tags: [],
        risk: { score: RISK_BY_SEVERITY[severity] ?? 40, severity, confidence: Number(c.confidence) || 0.7 },
      });
    });

  (web?.template_findings ?? [])
    .filter((t) => t.matched)
    .forEach((t, i) => {
      const severity = t.severity_hint || "Medium";
      findings.push({
        finding_id: `web-tmpl-${i}-${t.template_id}`,
        source_module: "web_scan",
        title: t.name,
        severity,
        confidence: 0.7,
        description: t.evidence ?? "",
        evidence: t.evidence ? [{ source: "web_scan", asset: t.url, evidence: t.evidence }] : [],
        affected_asset: t.url,
        tags: t.tags ?? [],
        risk: { score: RISK_BY_SEVERITY[severity] ?? 40, severity, confidence: 0.7 },
      });
    });

  (api?.template_matches ?? []).forEach((m, i) => {
    findings.push({
      finding_id: `api-tmpl-${i}-${m.template_id}`,
      source_module: "api_security",
      title: m.title,
      severity: m.severity,
      confidence: 0.75,
      description: m.evidence,
      evidence: [{ source: "api_security", asset: m.endpoint, evidence: m.evidence }],
      affected_asset: m.endpoint,
      remediation: m.remediation,
      tags: [],
      risk: { score: RISK_BY_SEVERITY[m.severity] ?? 50, severity: m.severity, confidence: 0.75 },
    });
  });

  (api?.auth_findings ?? []).forEach((msg, i) => {
    findings.push({
      finding_id: `api-auth-${i}`,
      source_module: "api_security",
      title: msg,
      severity: "Medium",
      confidence: 0.6,
      description: msg,
      evidence: [],
      affected_asset: api?.target,
      tags: ["auth"],
      risk: { score: RISK_BY_SEVERITY.Medium, severity: "Medium", confidence: 0.6 },
    });
  });

  const assets: Array<Record<string, unknown>> = [];
  (network?.addresses ?? []).forEach((addr) => assets.push({ type: "ip", value: addr, source: "network_scan" }));
  (network?.hostnames ?? []).forEach((h) => assets.push({ type: "hostname", value: h, source: "network_scan" }));
  (network?.open_ports ?? []).forEach((p) =>
    assets.push({ type: "service", value: `${p.port}/${p.protocol}`, service: p.service_name, source: "network_scan" })
  );
  (web?.endpoints ?? []).forEach((e) => assets.push({ type: "endpoint", value: e.url, method: e.method, source: "web_scan" }));
  (api?.endpoints ?? []).forEach((e) =>
    assets.push({ type: "api_endpoint", value: e.path, methods: e.methods, source: "api_security" })
  );

  const technologies: string[] = [];
  if (web?.server_header) technologies.push(web.server_header);

  const riskScore = findings.length
    ? Math.round(findings.reduce((sum, f) => sum + (f.risk?.score ?? 0), 0) / findings.length)
    : 0;

  const warnings = [...(network?.scan_warnings ?? []), ...(web?.scan_warnings ?? []), ...(api?.warnings ?? [])];

  return {
    scan_id: web?.scan_id ?? api?.scan_id ?? network?.scan_id ?? "partial",
    target,
    status: "completed",
    started_at: startedAt,
    finished_at: finishedAt,
    network_scan: network ?? undefined,
    web_scan: web ?? undefined,
    api_scan: api ?? undefined,
    findings,
    risk_score: riskScore,
    technologies,
    assets,
    warnings,
    dns: { addresses: network?.addresses ?? [] },
    tls: {},
    javascript_intelligence: { endpoints: web?.javascript_assets ?? [] },
  };
}
