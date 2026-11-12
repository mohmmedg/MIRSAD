import { useState } from "react";
import { Activity, Radar, Server } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ConfirmDialog, EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";
import { intervalLabel, statusTone } from "../format";

export function AdminAsmSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { asmInterval, asmSchedules, asmTarget, busy, createAsm, loading, removeAsmSchedule, setAsmInterval, setAsmTarget } = model;
  const [stopTarget, setStopTarget] = useState<Record<string, unknown> | null>(null);

  return (
    <div className="space-y-6">
      <Alert>
        <Radar aria-hidden="true" />
        <AlertTitle>{text(language, "المراقبة المستمرة لسطح الهجوم", "Continuous Attack Surface Monitoring")}</AlertTitle>
        <AlertDescription>
          {text(language,
            "تلتقط المراقبة التغييرات في عناوين IP والمنافذ والخدمات وDNS والتقنيات ونقاط النهاية وواجهات API وTLS، ثم تمررها إلى سلسلة الاكتشاف والمخاطر والتنبيهات والحوادث في مركز SOC.",
            "Deterministic snapshots detect changes to IPs, ports, services, DNS, technologies, endpoints, APIs and TLS, then feed the SOC finding → risk → alert → incident pipeline."
          )}
        </AlertDescription>
      </Alert>

      <SectionCard icon={Activity} title={text(language, "مراقبة هدف جديد", "Monitor a new target")}>
        <form
          className="grid gap-4 md:grid-cols-[minmax(0,1fr)_14rem_auto] md:items-end"
          onSubmit={(event) => {
            event.preventDefault();
            if (asmTarget.trim() && busy !== "asm") void createAsm();
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor="admin-asm-target">{text(language, "الهدف", "Target")}</Label>
            <Input id="admin-asm-target" dir="ltr" value={asmTarget} onChange={(event) => setAsmTarget(event.target.value)} placeholder="https://example.com" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="admin-asm-interval">{text(language, "التكرار", "Frequency")}</Label>
            <Select value={String(asmInterval)} onValueChange={(value) => setAsmInterval(Number(value))}>
              <SelectTrigger id="admin-asm-interval" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {[300, 900, 3600, 21600, 86400].map((seconds) => (
                  <SelectItem key={seconds} value={String(seconds)}>{intervalLabel(seconds, language)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button type="submit" disabled={busy === "asm" || !asmTarget.trim()}>
            {text(language, "بدء المراقبة", "Start monitoring")}
          </Button>
        </form>
      </SectionCard>

      <SectionCard icon={Server} title={text(language, "المراقبات", "Monitors")} description={text(language, `${asmSchedules.length} مراقبة`, `${asmSchedules.length} monitor(s)`)}>
        {loading && asmSchedules.length === 0 ? (
          <RowsSkeleton rows={3} />
        ) : asmSchedules.length === 0 ? (
          <EmptyState icon={Radar}>{text(language, "لا توجد مراقبات مستمرة مُعدّة حالياً.", "No continuous monitors configured.")}</EmptyState>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{text(language, "الهدف", "Target")}</TableHead>
                  <TableHead>{text(language, "التكرار", "Frequency")}</TableHead>
                  <TableHead>{text(language, "آخر حالة", "Last status")}</TableHead>
                  <TableHead className="text-end">{text(language, "إجراء", "Action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {asmSchedules.map((schedule) => {
                  const last = String(schedule.last_status || "");
                  return (
                    <TableRow key={String(schedule.schedule_id)}>
                      <TableCell className="max-w-[20rem]">
                        <Mono className="text-sm text-foreground">{String(schedule.target)}</Mono>
                        <Mono>{String(schedule.schedule_id)}</Mono>
                      </TableCell>
                      <TableCell>{intervalLabel(schedule.interval_seconds, language)}</TableCell>
                      <TableCell>
                        <StatusBadge tone={last ? statusTone(last) : "secondary"}>
                          {last || text(language, "لم يعمل بعد", "never run")}
                        </StatusBadge>
                      </TableCell>
                      <TableCell className="text-end">
                        <Button variant="ghost" size="sm" className="text-danger hover:text-danger" onClick={() => setStopTarget(schedule)}>
                          {text(language, "إيقاف", "Stop")}
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      <ConfirmDialog
        open={stopTarget !== null}
        onOpenChange={(open) => { if (!open) setStopTarget(null); }}
        title={text(language, "إيقاف هذه المراقبة؟", "Stop this monitor?")}
        description={text(language, `سيتوقف رصد ${String(stopTarget?.target ?? "")} ويُحذف جدول المراقبة.`, `Monitoring of ${String(stopTarget?.target ?? "")} stops and its schedule is deleted.`)}
        confirmLabel={text(language, "إيقاف المراقبة", "Stop monitoring")}
        cancelLabel={text(language, "إلغاء", "Cancel")}
        onConfirm={() => { if (stopTarget) void removeAsmSchedule(stopTarget); }}
      />
    </div>
  );
}
