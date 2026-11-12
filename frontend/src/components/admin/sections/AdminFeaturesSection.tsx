import { ToggleRight } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { Switch } from "@/components/ui/switch";
import { EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";
import { humanizeKey } from "../format";

export function AdminFeaturesSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { features, loading, toggleFeature } = model;
  const entries = Object.entries(features);
  const enabled = entries.filter(([, value]) => value).length;

  return (
    <SectionCard
      icon={ToggleRight}
      title={text(language, "مفاتيح الخصائص", "Feature flags")}
      description={entries.length ? text(language, `${enabled} مفعّلة من أصل ${entries.length}`, `${enabled} of ${entries.length} enabled`) : undefined}
    >
      {loading && entries.length === 0 ? (
        <RowsSkeleton />
      ) : entries.length === 0 ? (
        <EmptyState icon={ToggleRight}>{text(language, "لا توجد خصائص مهيأة للعرض.", "No feature flags are configured.")}</EmptyState>
      ) : (
        <ul className="grid gap-3 md:grid-cols-2">
          {entries.map(([key, value]) => (
            <li key={key} className="flex items-center justify-between gap-4 rounded-lg border bg-background/40 p-4">
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{humanizeKey(key)}</span>
                  <StatusBadge tone={value ? "success" : "secondary"}>
                    {value ? text(language, "مفعّل", "Enabled") : text(language, "معطّل", "Disabled")}
                  </StatusBadge>
                </div>
                <Mono>{key}</Mono>
              </div>
              <Switch
                checked={Boolean(value)}
                onCheckedChange={() => void toggleFeature(key)}
                aria-label={`${value ? text(language, "تعطيل", "Disable") : text(language, "تفعيل", "Enable")} ${key}`}
              />
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}
