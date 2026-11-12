import { useState } from "react";
import { LogOut, ShieldOff } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PaginationBar, usePagination } from "../AdminPagination";
import { SortHead, useSort } from "../AdminSort";
import { ConfirmDialog, EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";
import { formatDateTime } from "../format";

export function AdminSessionsSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { busy, loading, onRevokeAllSessions, onRevokeSession, sessions } = model;
  const [confirmAll, setConfirmAll] = useState(false);
  const { sorted, sort, toggle } = useSort(sessions, {
    user: (x) => x.user_id, started: (x) => Date.parse(x.created_at) || null, expires: (x) => Date.parse(x.expires_at) || null, status: (x) => (x.revoked ? 1 : 0),
  });
  const pager = usePagination(sorted, sort ? `${sort.key}${sort.dir}` : "");
  const active = sessions.filter((session) => !session.revoked).length;

  return (
    <>
      <SectionCard
        icon={LogOut}
        title={text(language, "الجلسات", "Sessions")}
        description={text(language, `${active} نشطة من أصل ${sessions.length}`, `${active} active of ${sessions.length}`)}
        actions={
          <Button variant="outline" size="sm" disabled={busy !== null || active === 0} onClick={() => setConfirmAll(true)}>
            <ShieldOff aria-hidden="true" />
            {text(language, "إبطال جميع الجلسات الأخرى", "Revoke all other sessions")}
          </Button>
        }
      >
        {loading && sessions.length === 0 ? (
          <RowsSkeleton />
        ) : sessions.length === 0 ? (
          <EmptyState icon={LogOut}>{text(language, "لا توجد جلسات لعرضها.", "No sessions to display.")}</EmptyState>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <SortHead id="user" sort={sort} onSort={toggle}>{text(language, "المستخدم", "User")}</SortHead>
                  <SortHead id="started" sort={sort} onSort={toggle}>{text(language, "بدأت", "Started")}</SortHead>
                  <SortHead id="expires" sort={sort} onSort={toggle}>{text(language, "تنتهي", "Expires")}</SortHead>
                  <SortHead id="status" sort={sort} onSort={toggle}>{text(language, "الحالة", "Status")}</SortHead>
                  <TableHead className="text-end">{text(language, "إجراء", "Action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pager.pageItems.map((session) => (
                  <TableRow key={session.id}>
                    <TableCell className="max-w-[16rem]"><Mono className="text-foreground">{session.user_id}</Mono></TableCell>
                    <TableCell className="text-muted-foreground">{formatDateTime(session.created_at, language)}</TableCell>
                    <TableCell className="text-muted-foreground">{formatDateTime(session.expires_at, language)}</TableCell>
                    <TableCell>
                      <StatusBadge tone={session.revoked ? "danger" : "success"}>
                        {session.revoked ? text(language, "ملغاة", "Revoked") : text(language, "نشطة", "Active")}
                      </StatusBadge>
                    </TableCell>
                    <TableCell className="text-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={session.revoked || busy === `session-${session.id}`}
                        onClick={() => void onRevokeSession(session.id)}
                      >
                        {text(language, "إبطال", "Revoke")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <PaginationBar {...pager} />
      </SectionCard>

      <ConfirmDialog
        open={confirmAll}
        onOpenChange={setConfirmAll}
        title={text(language, "إبطال جميع الجلسات الأخرى؟", "Revoke all other sessions?")}
        description={text(language, "سيُطلب من المستخدمين المتصلين تسجيل الدخول مجدداً.", "Signed-in users will need to sign in again.")}
        confirmLabel={text(language, "إبطال الجميع", "Revoke all")}
        cancelLabel={text(language, "إلغاء", "Cancel")}
        onConfirm={() => void onRevokeAllSessions()}
      />
    </>
  );
}
