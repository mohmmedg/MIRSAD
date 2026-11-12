import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, cleanup } from "@testing-library/react";
import React from "react";

const api = vi.hoisted(() => ({
  getActiveJobs: vi.fn(), getJob: vi.fn(), getScanHistoryRecords: vi.fn(),
}));
vi.mock("../../src/api/client", () => ({
  getActiveJobs: api.getActiveJobs, getJob: api.getJob, getScanHistoryRecords: api.getScanHistoryRecords,
  runAiAnalysis: vi.fn(), runRuleBasedAnalysis: vi.fn(), generateRuleBasedReport: vi.fn(), compareAnalysis: vi.fn(),
  getAttackSurfaceGraph: vi.fn(), ApiError: class ApiError extends Error { status = 0; },
}));
vi.mock("../../src/auth/supabase", () => ({ getTenantId: () => "t1", getAccessToken: () => "tok" }));
vi.mock("../../src/i18n/LanguageContext", () => ({ useLanguage: () => ({ language: "en", dir: "ltr", strings: { app: { genericError: "x" } } }) }));
vi.mock("../../src/offline/db", () => ({
  saveCurrentScanSnapshot: vi.fn().mockResolvedValue(undefined),
  clearCurrentScanSnapshot: vi.fn().mockResolvedValue(undefined),
  loadCurrentScanSnapshot: vi.fn().mockResolvedValue(null),
}));

import { ScanProvider, useScan } from "../../src/context/ScanContext";

const running = { job_id: "J1", job_type: "full", target: "http://x", status: "running", progress: 40 } as any;
const result = (id: string) => ({ scan_id: id, target: "http://x", status: "completed", findings: [] }) as any;
const completed = (id: string) => ({ ...running, job_id: id, status: "completed", progress: 100, result: result(id) });

function Probe() {
  const s = useScan();
  return <div>
    <span data-testid="sel">{s.activeScanId ?? "none"}</span>
    <button onClick={() => s.selectScan(result("H1"))} data-testid="pickH1" />
    <button onClick={() => void s.selectScanById("H2")} data-testid="pickH2" />
  </div>;
}
const mount = () => render(<ScanProvider><Probe /></ScanProvider>);
const flush = async (ms = 0) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };

beforeEach(() => {
  vi.useFakeTimers(); localStorage.clear();
  api.getActiveJobs.mockReset(); api.getJob.mockReset(); api.getScanHistoryRecords.mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("ScanProvider: scan lifecycle independent of the progress page", () => {
  it("a scan that finishes while the user is on another page lands in the workspace", async () => {
    localStorage.setItem("mirsad_active_scan_job", "J1");
    api.getActiveJobs.mockResolvedValueOnce([running]).mockResolvedValueOnce([running]).mockResolvedValue([]);
    api.getJob.mockResolvedValue(completed("J1"));
    mount();
    await flush(0);                       // hydration (still running)
    expect(screen.getByTestId("sel").textContent).toBe("none");
    await flush(3000 * 4);                // poller sees two empty answers in a row
    expect(screen.getByTestId("sel").textContent).toBe("J1");
    expect(localStorage.getItem("mirsad_active_scan_job")).toBeNull();
    expect(localStorage.getItem("mirsad_last_scan_job")).toBe("J1");
    expect(localStorage.getItem("mirsad_selected_scan_id")).toBe("J1");
  });

  it("one empty answer is not enough to conclude the scan ended", async () => {
    localStorage.setItem("mirsad_active_scan_job", "J1");
    api.getActiveJobs.mockResolvedValueOnce([running]).mockResolvedValueOnce([]).mockResolvedValue([running]);
    api.getJob.mockResolvedValue(completed("J1"));
    mount();
    await flush(0); await flush(3000 * 4);
    expect(api.getJob).not.toHaveBeenCalled();
    expect(localStorage.getItem("mirsad_active_scan_job")).toBe("J1");
    expect(screen.getByTestId("sel").textContent).toBe("none");
  });

  it("a finished scan never hijacks a scan the user opened from history in the meantime", async () => {
    localStorage.setItem("mirsad_active_scan_job", "J1");
    api.getActiveJobs.mockResolvedValueOnce([running]).mockResolvedValue([]);
    api.getJob.mockResolvedValue(completed("J1"));
    mount();
    await flush(0);
    act(() => { screen.getByTestId("pickH1").click(); });
    expect(screen.getByTestId("sel").textContent).toBe("H1");
    await flush(3000 * 4);
    expect(api.getJob).toHaveBeenCalled();                 // it did finalize...
    expect(screen.getByTestId("sel").textContent).toBe("H1"); // ...without replacing the user's choice
  });

  it("a job that is alive but not listed as active (cancel_requested) keeps being tracked", async () => {
    localStorage.setItem("mirsad_active_scan_job", "J1");
    api.getActiveJobs.mockResolvedValueOnce([running]).mockResolvedValue([]);
    api.getJob.mockResolvedValue({ ...running, status: "cancel_requested" });
    mount();
    await flush(0); await flush(3000 * 4);
    expect(localStorage.getItem("mirsad_active_scan_job")).toBe("J1");
    expect(screen.getByTestId("sel").textContent).toBe("none");
  });

  it("selectScan stores the history row id when the stored result lacks scan_id", async () => {
    mount(); await flush(0);
    api.getScanHistoryRecords.mockResolvedValue({ scans: [{ scan_id: "H2", target: "t", status: "completed", findings_count: 0, result: { target: "t", status: "completed", findings: [] } }], total: 1, limit: 50, offset: 0 });
    act(() => { screen.getByTestId("pickH2").click(); });
    await flush(0);
    expect(screen.getByTestId("sel").textContent).toBe("H2");
  });

  it("after a page reload the selected scan is restored from the backend", async () => {
    localStorage.setItem("mirsad_selected_scan_id", "H2");
    api.getActiveJobs.mockResolvedValue([]);
    api.getScanHistoryRecords.mockResolvedValue({ scans: [{ scan_id: "H2", target: "t", status: "completed", findings_count: 0, result: result("H2") }], total: 1, limit: 50, offset: 0 });
    mount();
    await flush(10);
    expect(screen.getByTestId("sel").textContent).toBe("H2");
  });

  it("restore drops the marker when the scan no longer exists, but keeps it if the backend is unreachable", async () => {
    localStorage.setItem("mirsad_selected_scan_id", "GONE");
    api.getActiveJobs.mockResolvedValue([]);
    api.getScanHistoryRecords.mockResolvedValue({ scans: [], total: 0, limit: 50, offset: 0 });
    mount(); await flush(10);
    expect(localStorage.getItem("mirsad_selected_scan_id")).toBeNull();
    cleanup();
    localStorage.setItem("mirsad_selected_scan_id", "H9");
    api.getScanHistoryRecords.mockRejectedValue(new Error("network"));
    mount(); await flush(10);
    expect(localStorage.getItem("mirsad_selected_scan_id")).toBe("H9");
  });
});
