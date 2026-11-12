import { Link } from "react-router-dom";
import type { LucideIcon } from "lucide-react";
import { Building2, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { useLanguage } from "../../i18n/LanguageContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { adminBasePath, type AdminSectionMeta } from "./adminRoutes";

export type { AdminTab } from "./adminRoutes";

export type AdminStatItem = {
  icon: LucideIcon;
  value: number;
  label: string;
  /** Semantic colour for the icon chip; severity colours are never decorative. */
  tone?: "default" | "danger" | "warning" | "success";
};

type TenantOption = { tenant_id: string; name: string };

type AdminPanelHeaderProps = {
  ownerMode: boolean;
  section: AdminSectionMeta;
  tenants: TenantOption[];
  selectedTenantId: string;
  onTenantChange: (tenantId: string) => void;
  onRefresh: () => void;
  refreshDisabled: boolean;
  loading: boolean;
};

const copy = {
  ar: {
    rootOwner: "إدارة المنصة",
    rootTenant: "إدارة المؤسسة",
    eyebrow: "MIRSAD · مركز التحكم",
    tenant: "المؤسسة المستهدفة",
    chooseTenant: "اختر المؤسسة",
    refresh: "تحديث",
    syncing: "جارٍ المزامنة",
    stats: "المؤشرات",
    statLabels: {
      Users: "المستخدمون", Active: "النشطون", Admins: "المديرون", "API keys": "مفاتيح API",
      Sessions: "الجلسات", "Active jobs": "المهام النشطة", "Open alerts": "التنبيهات المفتوحة",
      Critical: "حرجة", "Open incidents": "الحوادث المفتوحة", "Events / 24h": "الأحداث / 24 ساعة",
    },
  },
  en: {
    rootOwner: "Platform administration",
    rootTenant: "Organization administration",
    eyebrow: "MIRSAD · CONTROL CENTER",
    tenant: "Target organization",
    chooseTenant: "Select organization",
    refresh: "Refresh",
    syncing: "Syncing",
    stats: "Indicators",
    statLabels: {
      Users: "Users", Active: "Active", Admins: "Admins", "API keys": "API keys",
      Sessions: "Sessions", "Active jobs": "Active jobs", "Open alerts": "Open alerts",
      Critical: "Critical", "Open incidents": "Open incidents", "Events / 24h": "Events / 24h",
    },
  },
} as const;

export function AdminPanelHeader({
  ownerMode, section, tenants, selectedTenantId, onTenantChange, onRefresh, refreshDisabled, loading,
}: AdminPanelHeaderProps) {
  const { language } = useLanguage();
  const lang = language === "ar" ? "ar" : "en";
  const t = copy[lang];
  const root = ownerMode ? t.rootOwner : t.rootTenant;
  const isIndex = section.path === "";

  return (
    <header className="flex flex-col gap-5 border-b pb-6 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0 space-y-3">
        <Breadcrumb>
          <BreadcrumbList>
            <BreadcrumbItem>
              {isIndex ? (
                <BreadcrumbPage className="flex items-center gap-1.5">
                  <ShieldCheck className="size-3.5" aria-hidden="true" />
                  {root}
                </BreadcrumbPage>
              ) : (
                <BreadcrumbLink asChild>
                  <Link to={adminBasePath(ownerMode)} className="flex items-center gap-1.5">
                    <ShieldCheck className="size-3.5" aria-hidden="true" />
                    {root}
                  </Link>
                </BreadcrumbLink>
              )}
            </BreadcrumbItem>
            {!isIndex && (
              <>
                <BreadcrumbSeparator className="rtl:rotate-180" />
                <BreadcrumbItem>
                  <BreadcrumbPage>{section.label[lang]}</BreadcrumbPage>
                </BreadcrumbItem>
              </>
            )}
          </BreadcrumbList>
        </Breadcrumb>
        <div className="flex items-start gap-3">
          <span className="mt-0.5 grid size-10 shrink-0 place-items-center rounded-lg border bg-card text-primary shadow-sm">
            <section.icon className="size-5" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h1 className="text-xl leading-tight font-semibold tracking-tight text-balance sm:text-2xl">{section.title[lang]}</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{section.description[lang]}</p>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        {ownerMode && (
          <div className="flex min-w-[15rem] flex-col gap-1.5">
            <span className="flex items-center gap-1.5 font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
              <Building2 className="size-3" aria-hidden="true" />
              {t.tenant}
            </span>
            <Select value={selectedTenantId} onValueChange={onTenantChange}>
              <SelectTrigger aria-label={t.tenant} className="w-full bg-card">
                <SelectValue placeholder={t.chooseTenant} />
              </SelectTrigger>
              <SelectContent>
                {tenants.map((tenant) => (
                  <SelectItem key={tenant.tenant_id} value={tenant.tenant_id}>{tenant.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        <Button variant="outline" onClick={onRefresh} disabled={refreshDisabled} className="bg-card">
          {loading ? <Loader2 className="animate-spin" aria-hidden="true" /> : <RefreshCw aria-hidden="true" />}
          {t.refresh}
        </Button>
        {loading && (
          <Badge variant="info" role="status" className="self-center">{t.syncing}</Badge>
        )}
      </div>
    </header>
  );
}

const toneChip: Record<NonNullable<AdminStatItem["tone"]>, string> = {
  default: "bg-info-soft text-info",
  danger: "bg-danger-soft text-danger",
  warning: "bg-warning-soft text-warning",
  success: "bg-success-soft text-success",
};

export function AdminPanelStats({ items }: { items: AdminStatItem[] }) {
  const { language } = useLanguage();
  const t = copy[language === "ar" ? "ar" : "en"];

  if (items.length === 0) return null;

  return (
    <section
      className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,9.5rem),1fr))] gap-3"
      aria-label={t.stats}
    >
      {items.map(({ icon: Icon, value, label, tone = "default" }) => (
        <Card key={label} className="gap-3 p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">
              {t.statLabels[label as keyof typeof t.statLabels] ?? label}
            </span>
            <span className={cn("grid size-8 place-items-center rounded-md", toneChip[tone])}>
              <Icon className="size-4" aria-hidden="true" />
            </span>
          </div>
          <strong className="font-mono text-3xl leading-none font-semibold tabular-nums">
            {value.toLocaleString(language === "ar" ? "ar" : "en-US")}
          </strong>
        </Card>
      ))}
    </section>
  );
}
