import { NavLink } from "react-router-dom";
import {
  Activity,
  Bot,
  Boxes,
  ChartNoAxesCombined,
  FileText,
  LayoutDashboard,
  Network,
  ShieldCheck,
  Siren,
  Waypoints,
} from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import { MirsadMark } from "./MirsadMark";
import shell from "../App.module.css";

export interface NavEntry {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
}

export function Sidebar({ role }: { role: string | null }) {
  const { language } = useLanguage();
  const canManageTenant = role === "admin" || role === "owner";

  const nav: NavEntry[] = [
    { to: "/", label: language === "ar" ? "نظرة عامة" : "Overview", icon: LayoutDashboard },
    { to: "/scans", label: language === "ar" ? "الفحوصات" : "Scans", icon: Activity },
    { to: "/assets", label: language === "ar" ? "الأصول" : "Assets", icon: Boxes },
    { to: "/attack-surface", label: language === "ar" ? "سطح الهجوم" : "Attack Surface", icon: Waypoints },
    { to: "/findings", label: language === "ar" ? "الاكتشافات" : "Findings", icon: Siren },
    { to: "/risk", label: language === "ar" ? "المخاطر" : "Risk", icon: ChartNoAxesCombined },
    { to: "/reports", label: language === "ar" ? "التقارير" : "Reports", icon: FileText },
    { to: "/ai", label: language === "ar" ? "ذكاء Gemini" : "AI Intelligence", icon: Bot },
    { to: "/security", label: language === "ar" ? "الأمان والوصول" : "Security", icon: ShieldCheck },
  ];

  if (role === "admin" || role === "owner" || role === "analyst") {
    nav.push({ to: "/compliance", label: language === "ar" ? "الامتثال و CI/CD" : "Compliance & CI/CD", icon: ShieldCheck });
  }
  if (canManageTenant) {
    nav.push({ to: "/admin", label: language === "ar" ? "الإدارة" : "Admin", icon: ShieldCheck });
  }

  return (
    <aside className={shell.sidebar} aria-label="Primary navigation">
      <div className={shell.brandBlock}>
        <span className={shell.brandMark}>
          <MirsadMark size={18} />
        </span>
        <div>
          <strong>مرصاد</strong>
          <span>MIRSAD</span>
        </div>
      </div>

      <nav className={shell.nav}>
        <div className={shell.navLabel}>{language === "ar" ? "المنصة" : "Platform"}</div>
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) => `${shell.navItem} ${isActive ? shell.navActive : ""}`}
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className={shell.sidebarDivider} />
      <div className={shell.engineStatus}>
        <div className={shell.engineTitle}>
          <Network size={14} /> {language === "ar" ? "محركات الفحص" : "Scan engines"}
        </div>
        <span>
          <i /> Network
        </span>
        <span>
          <i /> Web crawler
        </span>
        <span>
          <i /> API security
        </span>
      </div>


    </aside>
  );
}
