import { Link } from "react-router-dom";
import { Activity, ArrowUpRight, Database } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { AdminPanelStats } from "../AdminPanelChrome";
import { ADMIN_GROUPS, ADMIN_SECTIONS, adminSectionPath } from "../adminRoutes";
import { EmptyState, SectionCard, StatusBadge } from "../AdminPrimitives";
import { humanizeKey, statusTone } from "../format";

export function AdminOverviewSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const lang = language === "ar" ? "ar" : "en";
  const { backup, health, overviewStats, ownerMode } = model;
  const healthEntries = Object.entries(health);
  const tools = ADMIN_SECTIONS.filter((section) => section.key !== "overview");

  return (
    <div className="space-y-6">
      <AdminPanelStats items={overviewStats} />

      <div className="grid items-start gap-6 lg:grid-cols-2">
        <SectionCard icon={Activity} title={text(language, "صحة المنصة", "Platform health")}>
          {healthEntries.length === 0 ? (
            <EmptyState icon={Activity}>{text(language, "بيانات صحة المنصة غير متاحة حالياً.", "Platform health data is not available yet.")}</EmptyState>
          ) : (
            <ul className="divide-y rounded-lg border">
              {healthEntries.map(([key, value]) => (
                <li key={key} className="flex items-center justify-between gap-3 px-4 py-3">
                  <span className="min-w-0 truncate text-sm font-medium" title={key}>{humanizeKey(key)}</span>
                  <StatusBadge tone={statusTone(String(value))}>{String(value)}</StatusBadge>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        <SectionCard icon={Database} title={text(language, "النسخ الاحتياطي والاستعادة", "Backup & recovery")}>
          {backup ? (
            <div className="space-y-3 rounded-lg border p-4">
              <StatusBadge tone={statusTone(backup.status)}>{backup.status || text(language, "غير معروف", "Unknown")}</StatusBadge>
              <p className="text-sm leading-relaxed text-muted-foreground">{backup.note}</p>
            </div>
          ) : (
            <EmptyState icon={Database}>{text(language, "لا توجد معلومات نسخ احتياطي متاحة.", "No backup information is available.")}</EmptyState>
          )}
        </SectionCard>
      </div>

      <section className="space-y-5 pt-2" aria-label={text(language, "أدوات الإدارة", "Administration tools")}>
        <h2 className="text-base font-semibold">{text(language, "أدوات الإدارة", "Administration tools")}</h2>
        {(Object.keys(ADMIN_GROUPS) as Array<keyof typeof ADMIN_GROUPS>)
          .filter((group) => tools.some((section) => section.group === group))
          .map((group) => (
            <div key={group} className="space-y-3">
              <h3 className="font-mono text-[10px] tracking-wider text-muted-foreground uppercase">{ADMIN_GROUPS[group][lang]}</h3>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {tools.filter((section) => section.group === group).map((section) => (
                  <Link
                    key={section.key}
                    to={adminSectionPath(ownerMode, section)}
                    className="group flex items-start gap-3 rounded-xl border bg-card p-4 shadow-sm transition-colors outline-none hover:border-primary/50 hover:bg-accent focus-visible:ring-[3px] focus-visible:ring-ring/50"
                  >
                    <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-info-soft text-info">
                      <section.icon className="size-4" aria-hidden="true" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-medium">{section.label[lang]}</span>
                      <span className="mt-0.5 line-clamp-2 block text-xs text-muted-foreground">{section.description[lang]}</span>
                    </span>
                    <ArrowUpRight className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:text-primary rtl:-scale-x-100" aria-hidden="true" />
                  </Link>
                ))}
              </div>
            </div>
          ))}
      </section>
    </div>
  );
}
