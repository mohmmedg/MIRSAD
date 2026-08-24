import { Route, Routes } from "react-router-dom";
import { AuthGate } from "./auth/AuthGate";
import { getRole } from "./auth/supabase";
import { TopBar } from "./components/TopBar";
import { Sidebar } from "./components/Sidebar";
import { ScanProvider, useScan } from "./context/ScanContext";
import { OverviewPage } from "./pages/OverviewPage";
import { ScansPage } from "./pages/ScansPage";
import { AssetsPage } from "./pages/AssetsPage";
import { AttackSurfacePage } from "./pages/AttackSurfacePage";
import { FindingsPage } from "./pages/FindingsPage";
import { RiskPage } from "./pages/RiskPage";
import { ReportsPage } from "./pages/ReportsPage";
import { AIPage } from "./pages/AIPage";
import { SecurityPage } from "./pages/SecurityPage";
import { CompliancePage } from "./pages/CompliancePage";
import { AdminPage } from "./pages/AdminPage";
import { useLanguage } from "./i18n/LanguageContext";
import shell from "./App.module.css";

function AppShell() {
  const { dir } = useLanguage();
  const role = getRole();
  const canManageTenant = role === "admin" || role === "owner";
  const canSeeCompliance = role === "admin" || role === "owner" || role === "analyst";
  const { searchQuery, setSearchQuery } = useScan();

  return (
    <div className="app-shell" dir={dir}>
      <TopBar searchQuery={searchQuery} onSearch={setSearchQuery} />
      <div className={shell.workspace}>
        <Sidebar role={role} />
        <main className="stage">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/attack-surface" element={<AttackSurfacePage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/risk" element={<RiskPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/ai" element={<AIPage />} />
            <Route path="/security" element={<SecurityPage />} />
            {canSeeCompliance && <Route path="/compliance" element={<CompliancePage />} />}
            {canManageTenant && <Route path="/admin" element={<AdminPage />} />}
            <Route path="*" element={<OverviewPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <AuthGate>
      <ScanProvider>
        <AppShell />
      </ScanProvider>
    </AuthGate>
  );
}

export default App;
