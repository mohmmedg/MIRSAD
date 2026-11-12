import { useState } from "react";
import { KeyRound, MoreHorizontal, Search, Trash2, UserCheck, UserPlus, UserX, Users } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import type { AdminUser } from "../../../api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PaginationBar, usePagination } from "../AdminPagination";
import { SortHead, useSort } from "../AdminSort";
import { ConfirmDialog, EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";

export function AdminUsersSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { busy, change, createUser, currentUserId, loading, newUserEmail, newUserPassword, ownerMode, permissions, removeUser, resetPassword, resetPasswordFor, resetPasswordValue, role, setNewUserEmail, setNewUserPassword, setResetPasswordFor, setResetPasswordValue, setUserFormOpen, userFormOpen, users } = model;
  const [query, setQuery] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<AdminUser | null>(null);

  const needle = query.trim().toLowerCase();
  const visible = needle
    ? users.filter((user) => user.email.toLowerCase().includes(needle) || user.tenant_name.toLowerCase().includes(needle))
    : users;
  const { sorted, sort, toggle } = useSort(visible, {
    user: (u) => u.email.toLowerCase(), role: (u) => u.role, status: (u) => (u.is_active ? 1 : 0),
  });
  const pager = usePagination(sorted, needle + (sort ? `${sort.key}${sort.dir}` : ""));
  const resetTarget = users.find((user) => user.user_id === resetPasswordFor) ?? null;

  const roleLabel: Record<AdminUser["role"], string> = {
    viewer: text(language, "متفرج — قراءة فقط", "Viewer — read only"),
    analyst: text(language, "فاحص — تشغيل وتحليل الفحوصات", "Analyst — run and analyze scans"),
    admin: text(language, "مدير — إدارة المستخدمين والسياسات", "Admin — manage users and policies"),
    owner: text(language, "مالك — صلاحيات كاملة", "Owner — full privileges"),
  };

  return (
    <div className="space-y-6">
      <SectionCard
        icon={Users}
        title={text(language, "إدارة الحسابات والصلاحيات", "Accounts & permissions")}
        description={text(language,
          "يبدأ كل حساب جديد بدور المتفرج (Viewer) الأقل صلاحية. ويمكن للمالك أو مدير المؤسسة رفع الصلاحية إلى فاحص (Analyst) أو مدير (Admin) وفق الحاجة.",
          `Every new account starts with the least-privileged Viewer role. ${ownerMode ? "The owner" : "The organization administrator"} can promote it to Analyst or Admin when required.`
        )}
        actions={
          <Button size="sm" onClick={() => setUserFormOpen(true)}>
            <UserPlus aria-hidden="true" />
            {text(language, "إنشاء حساب", "Create user")}
          </Button>
        }
      >
        <div className="relative max-w-sm">
          <Search className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            className="ps-9"
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={text(language, "ابحث بالبريد أو المؤسسة", "Search by email or organization")}
            aria-label={text(language, "بحث في المستخدمين", "Search users")}
          />
        </div>

        {loading && users.length === 0 ? (
          <RowsSkeleton rows={5} />
        ) : visible.length === 0 ? (
          <EmptyState icon={Users}>
            {users.length === 0
              ? text(language, "لا يوجد مستخدمون لعرضهم في هذه المؤسسة.", "No users are available for this organization.")
              : text(language, "لا توجد نتائج مطابقة للبحث.", "No users match your search.")}
          </EmptyState>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <SortHead id="user" sort={sort} onSort={toggle}>{text(language, "المستخدم", "User")}</SortHead>
                  <SortHead id="role" sort={sort} onSort={toggle}>{text(language, "الدور", "Role")}</SortHead>
                  <SortHead id="status" sort={sort} onSort={toggle}>{text(language, "الحالة", "Status")}</SortHead>
                  <TableHead className="w-12 text-end"><span className="sr-only">{text(language, "إجراءات", "Actions")}</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pager.pageItems.map((user) => {
                  const canChangeRole =
                    user.role !== "owner" &&
                    (role === "owner" || user.role === "viewer" || user.role === "analyst");
                  const canDelete =
                    user.user_id !== currentUserId &&
                    user.role !== "owner" &&
                    (role === "owner" || user.role !== "admin");
                  // Same hierarchy the backend enforces (_can_manage): the owner
                  // can reset anyone's password except another owner's; an admin
                  // can only reset viewer/analyst accounts, never another admin.
                  const canResetPassword =
                    role === "owner"
                      ? user.role !== "owner"
                      : user.role === "viewer" || user.role === "analyst";
                  const rowBusy = busy === user.user_id || busy === `delete-${user.user_id}`;
                  const canBlock = !rowBusy && user.role !== "owner" && (role === "owner" || user.role !== "admin");

                  return (
                    <TableRow key={user.user_id}>
                      <TableCell>
                       <div className="w-[min(20rem,62vw)]">
                        <div className="flex items-center gap-2">
                          <span className="truncate font-medium" title={user.email}>{user.email}</span>
                          {user.user_id === currentUserId && <Badge variant="outline">{text(language, "أنت", "You")}</Badge>}
                        </div>
                        <Mono>{user.user_id}</Mono>
                        <span className="block truncate text-xs text-muted-foreground">{text(language, "المؤسسة:", "Organization:")} {user.tenant_name}</span>
                       </div>
                      </TableCell>
                      <TableCell>
                        <Select
                          value={user.role}
                          disabled={rowBusy || !canChangeRole || (role !== "owner" && user.role === "admin") || user.role === "owner"}
                          onValueChange={(value) => void change(user, { role: value as AdminUser["role"] })}
                        >
                          <SelectTrigger size="sm" className="w-40" title={roleLabel[user.role]} aria-label={`${text(language, "دور", "Role of")} ${user.email}`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {user.role === "owner" && <SelectItem value="owner">{text(language, "مالك (Owner)", "Owner")}</SelectItem>}
                            <SelectItem value="viewer">{text(language, "متفرج (Viewer)", "Viewer")}</SelectItem>
                            <SelectItem value="analyst">{text(language, "فاحص (Analyst)", "Analyst")}</SelectItem>
                            <SelectItem value="admin">{text(language, "مدير (Admin)", "Admin")}</SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        <StatusBadge tone={user.is_active ? "success" : "danger"}>
                          {user.is_active ? text(language, "نشط", "Active") : text(language, "محظور", "Blocked")}
                        </StatusBadge>
                      </TableCell>
                      <TableCell className="text-end">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-sm" aria-label={`${text(language, "إجراءات", "Actions for")} ${user.email}`}>
                              <MoreHorizontal aria-hidden="true" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-56">
                            <DropdownMenuLabel className="truncate">{user.email}</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem disabled={!canBlock} onSelect={() => void change(user, { is_active: !user.is_active })}>
                              {user.is_active ? <UserX aria-hidden="true" /> : <UserCheck aria-hidden="true" />}
                              {user.is_active ? text(language, "حظر", "Block") : text(language, "فك الحظر", "Unblock")}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              disabled={!canResetPassword || busy === `reset-${user.user_id}`}
                              title={!canResetPassword ? text(language, "لا يمكنك إعادة تعيين كلمة مرور هذا الحساب", "You cannot reset this account password") : undefined}
                              onSelect={() => {
                                setResetPasswordValue("");
                                setResetPasswordFor(user.user_id);
                              }}
                            >
                              <KeyRound aria-hidden="true" />
                              {text(language, "إعادة تعيين كلمة المرور", "Reset password")}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              disabled={!canDelete || busy === `delete-${user.user_id}`}
                              title={!canDelete ? text(language, "لا يمكن حذف هذا الحساب", "This account cannot be deleted") : undefined}
                              onSelect={() => setDeleteTarget(user)}
                            >
                              <Trash2 aria-hidden="true" />
                              {text(language, "حذف نهائي", "Delete permanently")}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
        <PaginationBar {...pager} />
      </SectionCard>

      <SectionCard icon={KeyRound} title={text(language, "تدرج الصلاحيات", "Permission hierarchy")}>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {(
            [
              ["viewer", "Viewer / متفرج", text(language, "قراءة لوحة المعلومات والأصول والنتائج والتقارير.", "Read dashboards, assets, findings and reports.")],
              ["analyst", "Analyst / فاحص", text(language, "كل صلاحيات المتفرج، إضافة إلى تشغيل الفحوصات وتحليل النتائج والامتثال.", "All Viewer permissions plus scan execution, analysis and compliance.")],
              ["admin", "Admin / مدير", text(language, "كل صلاحيات الفاحص، إضافة إلى إدارة المستخدمين والجلسات والمفاتيح والسياسات والأمن.", "All Analyst permissions plus user, session, key, policy and security administration.")],
              ["owner", "Owner / مالك", text(language, "صلاحيات كاملة، ولا يمكن منح دور المالك من واجهة الإدارة.", "Full privileges. The Owner role cannot be assigned from this interface.")],
            ] as const
          ).map(([roleKey, label, description]) => (
            <div key={roleKey} className="flex flex-col gap-2 rounded-lg border bg-background/40 p-4">
              <b className="text-sm">{label}</b>
              <span className="text-xs leading-relaxed text-muted-foreground">{description}</span>
              {permissions[roleKey] && permissions[roleKey].length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {permissions[roleKey].map((perm) => (
                    <Badge key={perm} variant="outline" className="font-mono text-[10px]">{perm}</Badge>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </SectionCard>

      <Dialog open={userFormOpen} onOpenChange={setUserFormOpen}>
        <DialogContent>
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void createUser();
            }}
          >
            <DialogHeader>
              <DialogTitle>{text(language, "إنشاء حساب مستخدم جديد", "Create new user")}</DialogTitle>
              <DialogDescription>{text(language, "سيُنشأ الحساب بدور Viewer ويمكن رفع الصلاحية لاحقاً.", "The account is created as Viewer; the role can be raised later.")}</DialogDescription>
            </DialogHeader>
            <div className="grid gap-2">
              <Label htmlFor="admin-new-user-email">{text(language, "البريد الإلكتروني", "Email")}</Label>
              <Input
                id="admin-new-user-email"
                dir="ltr"
                type="email"
                value={newUserEmail}
                onChange={(event) => setNewUserEmail(event.target.value)}
                placeholder="user@example.com"
                autoComplete="off"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="admin-new-user-password">{text(language, "كلمة مرور مؤقتة", "Temporary password")}</Label>
              <Input
                id="admin-new-user-password"
                dir="ltr"
                type="password"
                value={newUserPassword}
                onChange={(event) => setNewUserPassword(event.target.value)}
                placeholder={text(language, "12 حرفاً على الأقل", "12+ characters")}
                autoComplete="new-password"
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setUserFormOpen(false)}>{text(language, "إلغاء", "Cancel")}</Button>
              <Button type="submit" disabled={busy === "new-user"}>
                <UserPlus aria-hidden="true" />
                {busy === "new-user" ? text(language, "جارٍ الإنشاء…", "Creating…") : text(language, "إنشاء بدور Viewer", "Create as Viewer")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={resetTarget !== null} onOpenChange={(open) => { if (!open) setResetPasswordFor(null); }}>
        <DialogContent>
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (resetTarget) void resetPassword(resetTarget);
            }}
          >
            <DialogHeader>
              <DialogTitle>{text(language, "إعادة تعيين كلمة المرور", "Reset password")}</DialogTitle>
              <DialogDescription className="break-all">{resetTarget?.email}</DialogDescription>
            </DialogHeader>
            <div className="grid gap-2">
              <Label htmlFor="admin-reset-password">{text(language, "كلمة مرور جديدة", "New password")}</Label>
              <Input
                id="admin-reset-password"
                dir="ltr"
                type="password"
                value={resetPasswordValue}
                onChange={(event) => setResetPasswordValue(event.target.value)}
                placeholder={text(language, "12 حرفاً على الأقل — أو اتركها فارغة للتوليد التلقائي", "12+ characters — or leave blank to generate one")}
                autoComplete="new-password"
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setResetPasswordFor(null)}>{text(language, "إلغاء", "Cancel")}</Button>
              <Button type="submit" disabled={resetTarget !== null && busy === `reset-${resetTarget.user_id}`}>
                <KeyRound aria-hidden="true" />
                {resetTarget !== null && busy === `reset-${resetTarget.user_id}` ? text(language, "جارٍ إعادة التعيين…", "Resetting…") : text(language, "تأكيد إعادة التعيين", "Confirm reset")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
        title={text(language, "حذف الحساب نهائياً؟", "Delete this account permanently?")}
        description={text(language, `حذف الحساب ${deleteTarget?.email ?? ""} نهائيًا من منصة MIRSAD؟`, `Permanently delete the account ${deleteTarget?.email ?? ""} from MIRSAD?`)}
        requireText={deleteTarget?.email}
        requireTextLabel={text(language, "اكتب بريد الحساب للتأكيد:", "Type the account email to confirm:")}
        confirmLabel={text(language, "حذف الحساب", "Delete account")}
        cancelLabel={text(language, "إلغاء", "Cancel")}
        onConfirm={() => { if (deleteTarget) void removeUser(deleteTarget); }}
      />
    </div>
  );
}
