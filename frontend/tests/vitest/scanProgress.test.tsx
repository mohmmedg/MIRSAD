import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, cleanup } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";
import React from "react";

const running = { job_id: "J1", job_type: "full_scan", target: "http://x", status: "running", progress: 60, stages: [], logs: [], current_engine: "api", elapsed_seconds: 10, created_at: new Date().toISOString() } as any;
const cancelled = { ...running, status: "cancelled", progress: 60 };

const api = vi.hoisted(() => ({
  getJob: vi.fn(), getActiveJobs: vi.fn(), pauseJob: vi.fn(), resumeJob: vi.fn(), cancelJob: vi.fn(),
  cachedJobs: {} as Record<string, any>,
}));
vi.mock("../../src/api/client", () => ({ getJob: api.getJob, getActiveJobs: api.getActiveJobs, pauseJob: api.pauseJob, resumeJob: api.resumeJob, cancelJob: api.cancelJob }));
vi.mock("../../src/auth/supabase", () => ({ getAccessToken: () => "tok" }));
vi.mock("../../src/i18n/LanguageContext", () => ({ useLanguage: () => ({ language: "en", dir: "ltr" }) }));
const stable = vi.hoisted(() => ({ apply: () => {}, cache: () => {}, activeScanId: null as string | null }));   // real context uses useCallback => stable refs
vi.mock("../../src/context/ScanContext", () => ({ useScan: () => ({ applyFullScanResult: stable.apply, cachedJobs: api.cachedJobs, cacheJob: stable.cache, activeScanId: stable.activeScanId }) }));

import { ScanProgressPage } from "../../src/pages/ScanProgressPage";

let sockets: FakeWS[] = [];
class FakeWS {
  static OPEN = 1; readyState = 0; onopen: any; onmessage: any; onclose: any; onerror: any;
  constructor(public url: string, public protocols: any) { sockets.push(this); }
  close() {}
  // helper the tests use to emulate the server
  serverOpen() { this.readyState = 1; this.onopen?.({}); }
  serverSend(o: any) { this.onmessage?.({ data: JSON.stringify(o) }); }
  serverClose(code = 1000) { this.readyState = 3; this.onclose?.({ code }); }
}

function Where() { const l = useLocation(); return <div data-testid="loc">{l.pathname}</div>; }
function App({ start }: { start: string }) {
  return <MemoryRouter initialEntries={[start]}><Where /><Routes>
    <Route path="/scan-progress" element={<ScanProgressPage />} />
    <Route path="/scan-progress/:jobId" element={<ScanProgressPage />} />
  </Routes></MemoryRouter>;
}
const flush = async (ms = 0) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };

beforeEach(() => {
  vi.useFakeTimers(); sockets = []; localStorage.clear(); api.cachedJobs = {}; stable.activeScanId = null;
  api.getJob.mockReset(); api.getActiveJobs.mockReset();
  (globalThis as any).WebSocket = FakeWS;
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("scan-progress page", () => {
  it("sidebar link (/scan-progress) jumps straight back to the running scan WITHOUT waiting for the network", async () => {
    localStorage.setItem("mirsad_active_scan_job", "J1");
    api.getActiveJobs.mockReturnValue(new Promise(() => {}));   // slow network: never answers
    api.getJob.mockReturnValue(new Promise(() => {}));
    api.cachedJobs = { J1: running };
    render(<App start="/scan-progress" />);
    await flush(0);
    expect(screen.getByTestId("loc").textContent).toBe("/scan-progress/J1");
    expect(api.getActiveJobs).not.toHaveBeenCalled();
    expect(screen.getAllByText(/60%/).length).toBeGreaterThan(0);        // last known state painted immediately
  });

  it("no stored id -> shows 'looking' state, then finds the active job", async () => {
    api.getActiveJobs.mockResolvedValue([running]); api.getJob.mockResolvedValue(running);
    render(<App start="/scan-progress" />);
    expect(screen.getByText(/Looking for a running scan/)).toBeTruthy();
    await flush(0);
    expect(screen.getByTestId("loc").textContent).toBe("/scan-progress/J1");
  });

  it("stale stored id (job gone, nothing running) is forgotten and the empty state shows", async () => {
    localStorage.setItem("mirsad_active_scan_job", "OLD");
    api.getJob.mockRejectedValue(Object.assign(new Error("Resource not found."), { status: 404, name: "ApiError" }));
    api.getActiveJobs.mockResolvedValue([]);
    render(<App start="/scan-progress" />);
    await flush(50);
    expect(localStorage.getItem("mirsad_active_scan_job")).toBeNull();
    expect(screen.getByTestId("loc").textContent).toBe("/scan-progress");
    expect(screen.getByText(/No active scan/)).toBeTruthy();
  });

  it("scan finished while the user was on another page: opens its final state instead of 'No active scan'", async () => {
    const completed = { ...running, status: "completed", progress: 100 };
    localStorage.setItem("mirsad_last_scan_job", "J1");           // set while it was running, never cleared on completion
    api.getActiveJobs.mockResolvedValue([]); api.getJob.mockResolvedValue(completed);
    render(<App start="/scan-progress" />);
    await flush(50);
    expect(screen.getByTestId("loc").textContent).toBe("/scan-progress/J1");
    expect(screen.queryByText(/No active scan/)).toBeNull();
    expect(screen.getAllByText(/100%/).length).toBeGreaterThan(0);
  });

  it("nothing running: falls back to the scan the workspace is on (e.g. opened from history)", async () => {
    stable.activeScanId = "H1";
    api.getActiveJobs.mockResolvedValue([]); api.getJob.mockResolvedValue({ ...running, job_id: "H1", status: "completed", progress: 100 });
    render(<App start="/scan-progress" />);
    await flush(50);
    expect(screen.getByTestId("loc").textContent).toBe("/scan-progress/H1");
  });

  it("last-scan id that no longer exists is dropped and does NOT redirect-loop", async () => {
    localStorage.setItem("mirsad_last_scan_job", "GONE");
    api.getActiveJobs.mockResolvedValue([]);
    api.getJob.mockRejectedValue(Object.assign(new Error("Resource not found."), { status: 404, name: "ApiError" }));
    render(<App start="/scan-progress" />);
    await flush(200);
    expect(localStorage.getItem("mirsad_last_scan_job")).toBeNull();
    expect(screen.getByTestId("loc").textContent).toBe("/scan-progress");
    expect(screen.getByText(/No active scan/)).toBeTruthy();
  });

  it("a finished job only clears the 'running' marker if it still points at that job", async () => {
    const completed = { ...running, job_id: "J1", status: "completed", progress: 100 };
    localStorage.setItem("mirsad_active_scan_job", "J2");        // a different scan started meanwhile
    api.getJob.mockResolvedValue(completed);
    render(<App start="/scan-progress/J1" />);
    await flush(0);
    expect(localStorage.getItem("mirsad_active_scan_job")).toBe("J2");
    expect(localStorage.getItem("mirsad_last_scan_job")).toBe("J1");
  });

  it("finished job: socket closed by server (1000) is NOT reconnected forever and polling stops", async () => {
    api.getJob.mockResolvedValue(cancelled);
    render(<App start="/scan-progress/J1" />);
    await flush(0);
    expect(sockets.length).toBe(1);
    act(() => { sockets[0].serverOpen(); sockets[0].serverSend(cancelled); sockets[0].serverClose(1000); });
    const jobCalls = api.getJob.mock.calls.length;
    await flush(60_000);                              // a full minute
    expect(sockets.length).toBe(1);                   // was: a new socket every ~1s (60+)
    expect(api.getJob.mock.calls.length).toBe(jobCalls); // and no more 2s polling either
    expect(localStorage.getItem("mirsad_active_scan_job")).toBeNull();
  });

  it("running job that really drops: reconnects with growing backoff (not every second)", async () => {
    api.getJob.mockResolvedValue(running);
    render(<App start="/scan-progress/J1" />);
    await flush(0);
    // server accepts then closes immediately, without ever sending data
    for (let i = 0; i < 6; i++) {
      const s = sockets[sockets.length - 1];
      act(() => { s.serverOpen(); s.serverClose(1006); });
      await flush(20_000);
    }
    const before = sockets.length;
    expect(before).toBeGreaterThan(2);
    // 60s of a flapping server should be roughly log2 attempts, far fewer than 60
    sockets = [];
    for (let i = 0; i < 20; i++) { const s = sockets[sockets.length - 1]; if (s) act(() => { s.serverOpen(); s.serverClose(1006); }); await flush(3_000); }
    expect(sockets.length).toBeLessThan(15);
  });

  it("close code 4404 (job not found on server) does not loop reconnecting", async () => {
    api.getJob.mockResolvedValue(running);
    render(<App start="/scan-progress/J1" />);
    await flush(0);
    act(() => { sockets[0].serverOpen(); sockets[0].serverClose(4404); });
    await flush(30_000);
    expect(sockets.length).toBe(1);
  });
});
