import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, cleanup, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import React from "react";

const api = vi.hoisted(() => ({
  getDefectDojoDashboard: vi.fn(), getDefectDojoFindings: vi.fn(), getDefectDojoFinding: vi.fn(),
  getScanDefectDojoStatus: vi.fn(), resyncScanToDefectDojo: vi.fn(),
}));
vi.mock("../../src/api/client", () => api);
vi.mock("../../src/i18n/LanguageContext", () => ({ useLanguage: () => ({ language: "en", dir: "ltr" }) }));
const ctx = vi.hoisted(() => ({ activeScanId: null as string | null }));
vi.mock("../../src/context/ScanContext", () => ({ useScan: () => ({ activeScanId: ctx.activeScanId }) }));

import { DefectDojoPage } from "../../src/pages/DefectDojoPage";

const sev = { Critical: 1, High: 2, Medium: 0, Low: 0, Info: 0 };
const dash = (scope: any = null) => ({ enabled: true, health: "AVAILABLE", url: "http://dd", products: 1, engagements: 1, tests: 1, findings: 3, findings_by_severity: sev, native_surfaces: [], scan_scope: scope, error: null });
const page = (scope: any = null, findings: any[] = []) => ({ enabled: true, health: "AVAILABLE", total: findings.length, limit: 25, offset: 0, findings, error: null, products: [], scan_scope: scope });
const finding = { id: 5, title: "Reflected XSS", severity: "High", date: null, active: true, verified: false, false_p: false, duplicate: false, risk_accepted: false, mitigated: null, cwe: null, cve: null, component: null, test: "t", engagement: "MIRSAD Scan S1", product: "p" };

const mount = (url = "/defectdojo") => render(<MemoryRouter initialEntries={[url]}><DefectDojoPage /></MemoryRouter>);
const settle = async () => { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); };

beforeEach(() => {
  Object.values(api).forEach((f) => (f as any).mockReset());
  ctx.activeScanId = null;
  api.getScanDefectDojoStatus.mockResolvedValue({ health: "AVAILABLE", mappings: [], jobs: [] });
});
afterEach(() => cleanup());

describe("DefectDojo page follows the selected scan", () => {
  it("scan selected (e.g. opened from history): list and counters are requested for THAT scan", async () => {
    ctx.activeScanId = "S1";
    api.getDefectDojoDashboard.mockResolvedValue(dash({ scan_id: "S1", synced: true, engagement_id: 70 }));
    api.getDefectDojoFindings.mockResolvedValue(page({ scan_id: "S1", synced: true, engagement_id: 70 }, [finding]));
    mount(); await settle();
    expect(api.getDefectDojoDashboard).toHaveBeenCalledWith("S1");
    expect(api.getDefectDojoFindings.mock.calls[0][0].scanId).toBe("S1");
    expect(screen.getByText("Reflected XSS")).toBeTruthy();
    expect(screen.getByText("S1")).toBeTruthy();
  });

  it("?scan=<id> deep link wins over the workspace selection", async () => {
    ctx.activeScanId = "S1";
    api.getDefectDojoDashboard.mockResolvedValue(dash()); api.getDefectDojoFindings.mockResolvedValue(page());
    mount("/defectdojo?scan=OTHER"); await settle();
    expect(api.getDefectDojoFindings.mock.calls[0][0].scanId).toBe("OTHER");
  });

  it("no scan selected: global view as before (no scan id sent)", async () => {
    api.getDefectDojoDashboard.mockResolvedValue(dash()); api.getDefectDojoFindings.mockResolvedValue(page());
    mount(); await settle();
    expect(api.getDefectDojoDashboard).toHaveBeenCalledWith(null);
    expect(api.getDefectDojoFindings.mock.calls[0][0].scanId).toBeNull();
  });

  it("user can switch to all scans and back", async () => {
    ctx.activeScanId = "S1";
    api.getDefectDojoDashboard.mockResolvedValue(dash()); api.getDefectDojoFindings.mockResolvedValue(page());
    mount(); await settle();
    fireEvent.click(screen.getByText("Show all scans")); await settle();
    expect(api.getDefectDojoFindings.mock.calls.at(-1)![0].scanId).toBeNull();
    fireEvent.click(screen.getByText("Show selected scan only")); await settle();
    expect(api.getDefectDojoFindings.mock.calls.at(-1)![0].scanId).toBe("S1");
  });

  it("scan not yet in DefectDojo: says so, shows sync state, and offers a manual sync", async () => {
    ctx.activeScanId = "S2";
    const scope = { scan_id: "S2", synced: false, engagement_id: null };
    api.getDefectDojoDashboard.mockResolvedValue(dash(scope)); api.getDefectDojoFindings.mockResolvedValue(page(scope));
    api.getScanDefectDojoStatus.mockResolvedValue({ health: "AVAILABLE", mappings: [], jobs: [{ status: "FAILED", last_error_code: "AUTH_ERROR" }] });
    api.resyncScanToDefectDojo.mockResolvedValue({ status: "PENDING" });
    mount(); await settle();
    expect(screen.getByText(/hasn't reached DefectDojo yet/)).toBeTruthy();
    expect(screen.getByText(/FAILED — AUTH_ERROR/)).toBeTruthy();
    fireEvent.click(screen.getByText("Sync this scan now")); await settle();
    expect(api.resyncScanToDefectDojo).toHaveBeenCalledWith("S2");
  });
});
