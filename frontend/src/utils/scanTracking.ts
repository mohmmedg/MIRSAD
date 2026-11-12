// utils/scanTracking.ts
//
// Browser-side bookkeeping for "which scan am I looking at / which one is running".
// Three independent markers, because they answer three different questions:
//
//   ACTIVE   - a server-side scan is still running. Removed as soon as it ends;
//              also drives the "leaving this page will not stop the scan" warning.
//   LAST     - the most recent scan this browser saw running. NEVER removed when
//              the scan finishes, so the progress page can still show its final
//              state (completed / failed / cancelled) instead of "no active scan".
//   SELECTED - the scan the whole workspace (findings, assets, DefectDojo...) is
//              scoped to. Set when a scan is opened from history or finishes.
//
// Everything here is best-effort: localStorage may be unavailable and none of
// these values is authoritative (the backend is).

export const ACTIVE_SCAN_KEY = "mirsad_active_scan_job";
export const LAST_SCAN_KEY = "mirsad_last_scan_job";
export const SELECTED_SCAN_KEY = "mirsad_selected_scan_id";

export const TERMINAL_JOB_STATUSES: ReadonlySet<string> = new Set(["completed", "partial", "failed", "cancelled"]);
export const LIVE_JOB_STATUSES: ReadonlySet<string> = new Set(["pending", "running", "paused", "cancel_requested"]);

export function readScanKey(key: string): string {
  try { return localStorage.getItem(key) ?? ""; } catch { return ""; }
}
export function writeScanKey(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
}
export function removeScanKey(key: string): void {
  try { localStorage.removeItem(key); } catch { /* storage unavailable */ }
}
