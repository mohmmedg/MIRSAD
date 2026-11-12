// Presentation helpers shared by the admin sections (no API access, no storage).
export type Tone = "success" | "warning" | "danger" | "info" | "secondary";

export function formatDateTime(value: unknown, language: string): string {
  if (value === null || value === undefined || value === "") return "—";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(language === "ar" ? "ar" : "en-GB", { dateStyle: "medium", timeStyle: "short" });
}

export function severityTone(severity: string): Tone {
  const value = severity.toLowerCase();
  if (value === "critical" || value === "high") return "danger";
  if (value === "medium") return "warning";
  if (value === "low" || value === "info") return "info";
  return "secondary";
}

export function statusTone(status: string): Tone {
  const value = status.toLowerCase();
  if (/^(ok|up|healthy|pass|passed|connected|ready|active|enabled|true|resolved|success)/.test(value)) return "success";
  if (/(fail|down|error|unhealthy|critical|disabled|false|revoked|blocked)/.test(value)) return "danger";
  if (/(degraded|warn|pending|open|unknown)/.test(value)) return "warning";
  if (/(acknowledged|running|info)/.test(value)) return "info";
  return "secondary";
}

export function humanizeKey(key: string): string {
  const spaced = key.replace(/[_.-]+/g, " ").trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : key;
}

export function intervalLabel(seconds: unknown, language: string): string {
  const n = Number(seconds);
  const ar = language === "ar";
  const known: Record<number, [string, string]> = {
    300: ["كل 5 دقائق", "Every 5 min"],
    900: ["كل 15 دقيقة", "Every 15 min"],
    3600: ["كل ساعة", "Every hour"],
    21600: ["كل 6 ساعات", "Every 6 hours"],
    86400: ["يومياً", "Daily"],
  };
  const hit = known[n];
  return hit ? hit[ar ? 0 : 1] : `${String(seconds)}s`;
}
