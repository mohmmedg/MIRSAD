import { Activity, Bell, Siren } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AdminPanelStats } from "../AdminPanelChrome";
import { EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";
import { formatDateTime, severityTone, statusTone } from "../format";

export function AdminSocSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { alerts, busy, incidents, loading, onUpdateAlert, onUpdateIncident, securityEvents, securityStats } = model;
  const waiting = loading && alerts.length === 0 && incidents.length === 0 && securityEvents.length === 0;

  return (
    <div className="space-y-6">
      <AdminPanelStats items={securityStats} />

      <Tabs defaultValue="alerts" className="gap-4">
        <TabsList className="h-auto flex-wrap">
          <TabsTrigger value="alerts"><Bell aria-hidden="true" />{text(language, "التنبيهات", "Alerts")}<Badge variant="secondary" className="ms-1 tabular-nums">{alerts.length}</Badge></TabsTrigger>
          <TabsTrigger value="incidents"><Siren aria-hidden="true" />{text(language, "الحوادث", "Incidents")}<Badge variant="secondary" className="ms-1 tabular-nums">{incidents.length}</Badge></TabsTrigger>
          <TabsTrigger value="timeline"><Activity aria-hidden="true" />{text(language, "الخط الزمني", "Timeline")}<Badge variant="secondary" className="ms-1 tabular-nums">{securityEvents.length}</Badge></TabsTrigger>
        </TabsList>

        <TabsContent value="alerts">
          <SectionCard icon={Bell} title={text(language, "التنبيهات الأمنية", "Security alerts")}>
            {waiting ? <RowsSkeleton /> : alerts.length === 0 ? (
              <EmptyState icon={Bell}>{text(language, "لا توجد تنبيهات أمنية حالياً.", "No security alerts at this time.")}</EmptyState>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{text(language, "التنبيه", "Alert")}</TableHead>
                      <TableHead>{text(language, "الخطورة", "Severity")}</TableHead>
                      <TableHead>{text(language, "الحالة", "Status")}</TableHead>
                      <TableHead>{text(language, "الوقت", "Time")}</TableHead>
                      <TableHead className="text-end">{text(language, "إجراء", "Action")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.slice(0, 25).map((alert) => (
                      <TableRow key={alert.alert_id}>
                        <TableCell className="max-w-[22rem]">
                          <div className="truncate font-medium" title={alert.title}>{alert.title}</div>
                          <Mono>{`${alert.event_id || "event"} · risk ${alert.risk_score}`}</Mono>
                        </TableCell>
                        <TableCell><StatusBadge tone={severityTone(alert.severity)}>{alert.severity}</StatusBadge></TableCell>
                        <TableCell><StatusBadge tone={statusTone(alert.status)}>{alert.status}</StatusBadge></TableCell>
                        <TableCell className="text-muted-foreground">{formatDateTime(alert.created_at, language)}</TableCell>
                        <TableCell className="text-end">
                          {alert.status !== "resolved" && (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={alert.status === "acknowledged" || busy === `alert-${alert.alert_id}`}
                              onClick={() => void onUpdateAlert(alert.alert_id)}
                            >
                              {text(language, "تأكيد الاستلام", "Acknowledge")}
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </SectionCard>
        </TabsContent>

        <TabsContent value="incidents">
          <SectionCard icon={Siren} title={text(language, "مركز الحوادث", "Incident Center")}>
            {waiting ? <RowsSkeleton /> : incidents.length === 0 ? (
              <EmptyState icon={Siren}>{text(language, "لا توجد حوادث مفتوحة أو مسجلة.", "No incidents are currently recorded.")}</EmptyState>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{text(language, "الحادث", "Incident")}</TableHead>
                      <TableHead>{text(language, "الخطورة", "Severity")}</TableHead>
                      <TableHead>{text(language, "الحالة", "Status")}</TableHead>
                      <TableHead>{text(language, "الوقت", "Time")}</TableHead>
                      <TableHead className="text-end">{text(language, "إجراء", "Action")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {incidents.slice(0, 25).map((incident) => (
                      <TableRow key={incident.incident_id}>
                        <TableCell className="max-w-[22rem]">
                          <div className="truncate font-medium" title={incident.title}>{incident.title}</div>
                          <Mono>{incident.incident_id}</Mono>
                        </TableCell>
                        <TableCell><StatusBadge tone={severityTone(incident.severity)}>{incident.severity}</StatusBadge></TableCell>
                        <TableCell><StatusBadge tone={statusTone(incident.status)}>{incident.status}</StatusBadge></TableCell>
                        <TableCell className="text-muted-foreground">{formatDateTime(incident.created_at, language)}</TableCell>
                        <TableCell className="text-end">
                          {incident.status !== "resolved" && (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={busy === `incident-${incident.incident_id}`}
                              onClick={() => void onUpdateIncident(incident.incident_id)}
                            >
                              {text(language, "حل الحادث", "Resolve")}
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </SectionCard>
        </TabsContent>

        <TabsContent value="timeline">
          <SectionCard icon={Activity} title={text(language, "الخط الزمني للاكتشافات", "Detection timeline")}>
            {waiting ? <RowsSkeleton /> : securityEvents.length === 0 ? (
              <EmptyState icon={Activity}>{text(language, "لا توجد أحداث اكتشاف خلال الفترة الحالية.", "No detection events in the current period.")}</EmptyState>
            ) : (
              <ol className="relative space-y-0 border-s ps-6">
                {securityEvents.slice(0, 30).map((event) => (
                  <li key={event.event_id} className="relative pb-5 last:pb-0">
                    <span className="absolute -start-[1.9rem] top-1.5 size-2.5 rounded-full border-2 border-background bg-primary" aria-hidden="true" />
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium">{event.event_type}</span>
                      <StatusBadge tone={severityTone(event.severity)}>{event.severity}</StatusBadge>
                      <span className="font-mono text-xs text-muted-foreground">risk {event.risk_score}</span>
                    </div>
                    <div className="mt-0.5 text-xs text-muted-foreground">{formatDateTime(event.created_at, language)}</div>
                  </li>
                ))}
              </ol>
            )}
          </SectionCard>
        </TabsContent>
      </Tabs>
    </div>
  );
}
