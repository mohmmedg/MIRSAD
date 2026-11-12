import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import { Save, SlidersHorizontal } from "lucide-react";
import { useLanguage } from "../../i18n/LanguageContext";
import { adminSectionText as text } from "./sectionText";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { EmptyState, Mono, SectionCard } from "./AdminPrimitives";
import { humanizeKey } from "./format";

export function PolicyCard({
  title,
  icon,
  values,
  onToggle,
  onSaveValues,
  busy,
}: {
  title: string;
  icon: LucideIcon;
  values: Record<string, unknown>;
  onToggle: (key: string, value: boolean) => void;
  onSaveValues: (changed: Record<string, unknown>) => void;
  busy: boolean;
}) {
  // مسودة محلية للحقول الرقمية/النصية فقط؛ الحقول Boolean تُبدَّل فوراً (onToggle)
  // لأنها لا تحتاج تأكيداً، والقيم الأخرى تُحفظ دفعة واحدة بزر «حفظ التغييرات».
  const { language } = useLanguage();
  const [draft, setDraft] = useState<Record<string, string>>({});

  const entries = Object.entries(values);
  const editableEntries = entries.filter(([, v]) => typeof v !== "boolean");
  const hasChanges = editableEntries.some(
    ([key, value]) => draft[key] !== undefined && draft[key] !== String(value ?? "")
  );

  function fieldValue(key: string, value: unknown): string {
    return draft[key] ?? String(value ?? "");
  }

  function save() {
    const changed: Record<string, unknown> = {};
    for (const [key, value] of editableEntries) {
      const current = draft[key];
      if (current === undefined) continue;
      if (current === String(value ?? "")) continue;
      changed[key] = typeof value === "number" ? Number(current) : current;
    }
    if (Object.keys(changed).length === 0) return;
    onSaveValues(changed);
    setDraft({});
  }

  return (
    <SectionCard
      icon={icon}
      title={title}
      actions={
        hasChanges ? (
          <Button size="sm" onClick={save} disabled={busy}>
            <Save aria-hidden="true" />
            {text(language, "حفظ التغييرات", "Save changes")}
          </Button>
        ) : undefined
      }
    >
      {entries.length === 0 ? (
        <EmptyState icon={SlidersHorizontal}>{text(language, "لا توجد إعدادات متاحة في هذا القسم.", "No settings are available in this section.")}</EmptyState>
      ) : (
        <ul className="divide-y rounded-lg border">
          {entries.map(([key, value]) => (
            <li key={key} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">{humanizeKey(key)}</div>
                <Mono>{key}</Mono>
              </div>
              {typeof value === "boolean" ? (
                <Switch
                  checked={value}
                  disabled={busy}
                  onCheckedChange={() => onToggle(key, !value)}
                  aria-label={`${humanizeKey(key)}: ${value ? text(language, "مفعّل", "Enabled") : text(language, "معطّل", "Disabled")}`}
                />
              ) : (
                <Input
                  dir="ltr"
                  className="h-8 w-32 shrink-0 text-end font-mono"
                  aria-label={humanizeKey(key)}
                  type={typeof value === "number" ? "number" : "text"}
                  value={fieldValue(key, value)}
                  disabled={busy}
                  onChange={(e) => setDraft((current) => ({ ...current, [key]: e.target.value }))}
                  onKeyDown={(e) => { if (e.key === "Enter") save(); }}
                />
              )}
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}
