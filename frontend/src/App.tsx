import { Suspense, lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AuthGate } from "./auth/AuthGate";
import { getRole } from "./auth/supabase";
import { TopBar } from "./components/TopBar";
import { Sidebar } from "./components/Sidebar";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ScanProvider, useScan } from "./context/ScanContext";
// 2026-09-19 fix: these were static imports, so Vite pulled every page's
// module graph (and everything each page imports - see AdminPanel,
// ReportView, ComplianceCenter, etc.) into the request chain before the
// login screen could even paint, regardless of which single route the user
// was about to see. A DevTools trace showed this as ~40+ separate .tsx/.css
// requests completing before LCP, accounting for most of the "load delay"
// subpart of LCP (546ms of the 651ms total). React.lazy() turns each of
// these into its own chunk that Vite only requests once that route actually
// renders, so the login screen's critical path no longer includes code for
// pages the user hasn't navigated to yet. Named exports need the
// `.then(m => ({ default: m.X }))` wrapper since lazy() expects a default
// export.
const OverviewPage = lazy(() => import("./pages/OverviewPage").then((m) => ({ default: m.OverviewPage })));
const ScansPage = lazy(() => import("./pages/ScansPage").then((m) => ({ default: m.ScansPage })));
const ScanHistoryPage = lazy(() => import("./pages/ScanHistoryPage").then((m) => ({ default: m.ScanHistoryPage })));
const RawScanResultsPage = lazy(() => import("./pages/RawScanResultsPage").then((m) => ({ default: m.RawScanResultsPage })));
const ScanExecutionPage = lazy(() => import("./pages/ScanExecutionPage").then((m) => ({ default: m.ScanExecutionPage })));
const AssetsPage = lazy(() => import("./pages/AssetsPage").then((m) => ({ default: m.AssetsPage })));
const AttackSurfacePage = lazy(() => import("./pages/AttackSurfacePage").then((m) => ({ default: m.AttackSurfacePage })));
const ScanProgressPage = lazy(() => import("./pages/ScanProgressPage").then((m) => ({ default: m.ScanProgressPage })));
const AttackSurfaceIntelligenceGraphPage = lazy(() => import("./pages/AttackSurfaceIntelligenceGraphPage").then((m) => ({ default: m.AttackSurfaceIntelligenceGraphPage })));
const FindingsPage = lazy(() => import("./pages/FindingsPage").then((m) => ({ default: m.FindingsPage })));
const RiskPage = lazy(() => import("./pages/RiskPage").then((m) => ({ default: m.RiskPage })));
const ReportsPage = lazy(() => import("./pages/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const AIPage = lazy(() => import("./pages/AIPage").then((m) => ({ default: m.AIPage })));
const SecurityPage = lazy(() => import("./pages/SecurityPage").then((m) => ({ default: m.SecurityPage })));
const DefectDojoPage = lazy(() => import("./pages/DefectDojoPage").then((m) => ({ default: m.DefectDojoPage })));
const CompliancePage = lazy(() => import("./pages/CompliancePage").then((m) => ({ default: m.CompliancePage })));
const AdminPage = lazy(() => import("./pages/AdminPage").then((m) => ({ default: m.AdminPage })));
const TenantAdminPage = lazy(() => import("./pages/TenantAdminPage").then((m) => ({ default: m.TenantAdminPage })));
const AdminSectionRoute = lazy(() => import("./components/admin/AdminSectionRoute").then((m) => ({ default: m.AdminSectionRoute })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));
import { ADMIN_SECTIONS } from "./components/admin/adminRoutes";
import { useLanguage } from "./i18n/LanguageContext";
import { ThemeProvider } from "./context/ThemeContext";
import shell from "./App.module.css";
import { ActiveScanBar } from "./components/ActiveScanBar";

function AppShell() {
  const { dir } = useLanguage();
  const role = getRole();
  const canManageTenant = role === "admin";
  const canManagePlatform = role === "owner";
  const canSeeCompliance = role === "admin" || role === "owner" || role === "analyst";
  const { searchQuery, setSearchQuery } = useScan();

  return (
    <div className="app-shell" dir={dir}>
      <TopBar searchQuery={searchQuery} onSearch={setSearchQuery} />
      <ActiveScanBar />
      <div className={shell.workspace}>
        <Sidebar role={role} />
        <main className="stage">
          <ErrorBoundary label="الصفحة الحالية" inline>
            <Suspense fallback={<div className="pageLoading" aria-busy="true" />}>
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/scans" element={<ScansPage />} />
                <Route path="/scan-history" element={<ScanHistoryPage />} />
                <Route path="/scan-history/:scanId/raw" element={<RawScanResultsPage />} />
                <Route path="/raw-results" element={<RawScanResultsPage />} />
                <Route path="/raw-results/:scanId" element={<RawScanResultsPage />} />
                <Route path="/scan-execution" element={<ScanExecutionPage />} />
                <Route path="/scan-execution/:scanId" element={<ScanExecutionPage />} />
                <Route path="/scan-progress" element={<ScanProgressPage />} />
                <Route path="/scan-progress/:jobId" element={<ScanProgressPage />} />
                <Route path="/assets" element={<AssetsPage />} />
                <Route path="/attack-surface" element={<AttackSurfacePage />} />
                <Route path="/attack-surface-intelligence" element={<AttackSurfaceIntelligenceGraphPage />} />
                <Route path="/attack-surface-intelligence/:scanId" element={<AttackSurfaceIntelligenceGraphPage />} />
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/risk" element={<RiskPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/ai" element={<AIPage />} />
                <Route path="/security" element={<SecurityPage />} />
                <Route path="/defectdojo" element={<DefectDojoPage />} />
                {canSeeCompliance && <Route path="/compliance" element={<CompliancePage />} />}
                {canManagePlatform && (
                  <Route path="/admin" element={<AdminPage />}>
                    {ADMIN_SECTIONS.map((section) => section.path === ""
                      ? <Route key={section.key} index element={<AdminSectionRoute section={section.key} />} />
                      : <Route key={section.key} path={section.path} element={<AdminSectionRoute section={section.key} />} />)}
                    <Route path="*" element={<Navigate to="/admin" replace />} />
                  </Route>
                )}
                {canManageTenant && (
                  <Route path="/tenant-admin" element={<TenantAdminPage />}>
                    {ADMIN_SECTIONS.map((section) => section.path === ""
                      ? <Route key={section.key} index element={<AdminSectionRoute section={section.key} />} />
                      : <Route key={section.key} path={section.path} element={<AdminSectionRoute section={section.key} />} />)}
                    <Route path="*" element={<Navigate to="/tenant-admin" replace />} />
                  </Route>
                )}
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<OverviewPage />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary label="التطبيق">
      <AuthGate>
        <ScanProvider>
          <ThemeProvider>
            <AppShell />
          </ThemeProvider>
        </ScanProvider>
      </AuthGate>
    </ErrorBoundary>
  );
}

export default App;
