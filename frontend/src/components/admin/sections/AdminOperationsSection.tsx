import { ScrollText, Server } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";
import { formatDateTime, humanizeKey } from "../format";

export function AdminOperationsSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { audit, loading, scan } = model;
  const controls = Object.entries(scan);

  return (
    <div className="space-y-6">
      <SectionCard icon={Server} title={text(language, "عناصر التحكم التشغيلية", "Operational controls")}>
        {loading && controls.length === 0 ? (
          <RowsSkeleton rows={3} />
        ) : controls.length === 0 ? (
          <EmptyState icon={Server}>{text(language, "بيانات التشغيل غير متاحة حالياً.", "Operational data is not available yet.")}</EmptyState>
        ) : (
          <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {controls.map(([key, value]) => (
              <div key={key} className="min-w-0 space-y-1.5 rounded-lg border bg-background/40 p-4">
                <dt className="truncate text-xs text-muted-foreground" title={key}>{humanizeKey(key)}</dt>
                <dd>
                  {typeof value === "boolean" ? (
                    <StatusBadge tone={value ? "success" : "secondary"}>{value ? text(language, "مفعّل", "Enabled") : text(language, "معطّل", "Disabled")}</StatusBadge>
                  ) : (
                    <span className="font-mono text-lg font-semibold tabular-nums">{String(value)}</span>
                  )}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </SectionCard>

      <SectionCard icon={ScrollText} title={text(language, "أحدث أحداث التدقيق", "Recent audit events")}>
        {loading && audit.length === 0 ? (
          <RowsSkeleton />
        ) : audit.length === 0 ? (
          <EmptyState icon={ScrollText}>{text(language, "لا توجد أحداث تدقيق حديثة.", "No recent audit events.")}</EmptyState>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{text(language, "الحدث", "Event")}</TableHead>
                  <TableHead>{text(language, "الهدف", "Target")}</TableHead>
                  <TableHead className="text-end">{text(language, "الوقت", "Time")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {audit.map((event, index) => (
                  <TableRow key={String(event.id ?? index)}>
                    <TableCell className="font-medium">{String(event.event)}</TableCell>
                    <TableCell className="max-w-[18rem]"><Mono className="text-foreground">{String(event.target ?? "—")}</Mono></TableCell>
                    <TableCell className="text-end text-muted-foreground">{formatDateTime(event.created_at, language)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
