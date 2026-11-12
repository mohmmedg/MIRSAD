import { useMemo, useState } from "react";
import { Download, ScrollText, Search } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, Mono, RowsSkeleton, SectionCard } from "../AdminPrimitives";
import { formatDateTime } from "../format";

type AuditEvent = Record<string, unknown>;
const PAGE = 20;

/** CSV cell: quote, double inner quotes, and defuse spreadsheet formulas (=, +, -, @). */
function csvCell(value: unknown): string {
  let s = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

export function AdminAuditCard({ audit, loading }: { audit: AuditEvent[]; loading: boolean }) {
  const { language } = useLanguage();
  const [query, setQuery] = useState("");
  const [eventFilter, setEventFilter] = useState("all");
  const [limit, setLimit] = useState(PAGE);

  const eventNames = useMemo(() => Array.from(new Set(audit.map((e) => String(e.event)))).sort(), [audit]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return audit.filter((e) =>
      (eventFilter === "all" || String(e.event) === eventFilter) &&
      (!q || `${e.event} ${e.target ?? ""}`.toLowerCase().includes(q)));
  }, [audit, query, eventFilter]);
  const visible = filtered.slice(0, limit);

  function exportCsv() {
    const rows = [["event", "target", "created_at"], ...filtered.map((e) => [e.event, e.target, e.created_at])];
    const blob = new Blob(["﻿" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mirsad-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <SectionCard
      icon={ScrollText}
      title={text(language, "سجل التدقيق", "Audit")}
      description={text(language, `${filtered.length} من ${audit.length} حدثاً محمّلاً`, `${filtered.length} of ${audit.length} loaded events`)}
      actions={
        <Button variant="outline" size="sm" onClick={exportCsv} disabled={filtered.length === 0}>
          <Download aria-hidden="true" />{text(language, "تصدير CSV", "Export CSV")}
        </Button>
      }
    >
      {loading && audit.length === 0 ? (
        <RowsSkeleton />
      ) : audit.length === 0 ? (
        <EmptyState icon={ScrollText}>{text(language, "لا توجد أحداث تدقيق حديثة.", "No recent audit events.")}</EmptyState>
      ) : (
        <>
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
              <Input
                value={query}
                onChange={(e) => { setQuery(e.target.value); setLimit(PAGE); }}
                placeholder={text(language, "ابحث بالحدث أو الهدف…", "Search event or target…")}
                aria-label={text(language, "بحث في سجل التدقيق", "Search audit log")}
                className="ps-9"
                maxLength={120}
              />
            </div>
            <Select value={eventFilter} onValueChange={(v) => { setEventFilter(v); setLimit(PAGE); }}>
              <SelectTrigger className="w-full sm:w-52" aria-label={text(language, "تصفية بالحدث", "Filter by event")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{text(language, "كل الأحداث", "All events")}</SelectItem>
                {eventNames.map((name) => <SelectItem key={name} value={name}>{name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          {filtered.length === 0 ? (
            <EmptyState icon={Search}>{text(language, "لا توجد أحداث مطابقة.", "No matching events.")}</EmptyState>
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
                  {visible.map((event, index) => (
                    <TableRow key={String(event.id ?? index)}>
                      <TableCell className="font-medium">{String(event.event)}</TableCell>
                      <TableCell className="max-w-[10rem]"><Mono className="text-foreground">{String(event.target ?? "—")}</Mono></TableCell>
                      <TableCell className="text-end text-muted-foreground">{formatDateTime(event.created_at, language)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {filtered.length > visible.length && (
            <Button variant="ghost" size="sm" className="w-full" onClick={() => setLimit((n) => n + PAGE)}>
              {text(language, `عرض المزيد (${filtered.length - visible.length})`, `Show more (${filtered.length - visible.length})`)}
            </Button>
          )}
        </>
      )}
    </SectionCard>
  );
}
