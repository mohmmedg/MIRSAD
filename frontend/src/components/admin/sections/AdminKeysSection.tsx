import { useState } from "react";
import { KeyRound, Plus } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SortHead, useSort } from "../AdminSort";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ConfirmDialog, EmptyState, Mono, RowsSkeleton, SectionCard, StatusBadge } from "../AdminPrimitives";
import { formatDateTime } from "../format";

export function AdminKeysSection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { busy, keyExpiryDays, keyFormOpen, keyName, keys, loading, makeKey, onRevokeKey, setKeyExpiryDays, setKeyFormOpen, setKeyName } = model;
  const { sorted, sort, toggle } = useSort(keys, {
    key: (k) => (k.name || k.key_id).toLowerCase(), expires: (k) => (k.expires_at ? Date.parse(k.expires_at) : null),
    last: (k) => (k.last_used_at ? Date.parse(k.last_used_at) : null), status: (k) => (k.revoked ? 1 : 0),
  });
  const [revokeTarget, setRevokeTarget] = useState<(typeof keys)[number] | null>(null);

  return (
    <>
      <SectionCard
        icon={KeyRound}
        title={text(language, "مفاتيح API", "API keys")}
        description={text(language, "يظهر سر المفتاح مرة واحدة فقط عند إنشائه.", "A key's secret is shown only once, when it is created.")}
        actions={
          <Button size="sm" onClick={() => setKeyFormOpen(true)}>
            <Plus aria-hidden="true" />
            {text(language, "إنشاء مفتاح", "Create key")}
          </Button>
        }
      >
        {loading && keys.length === 0 ? (
          <RowsSkeleton />
        ) : keys.length === 0 ? (
          <EmptyState icon={KeyRound}>{text(language, "لا توجد مفاتيح API لهذه المؤسسة.", "No API keys exist for this organization.")}</EmptyState>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <SortHead id="key" sort={sort} onSort={toggle}>{text(language, "المفتاح", "Key")}</SortHead>
                  <TableHead>{text(language, "النطاقات", "Scopes")}</TableHead>
                  <SortHead id="expires" sort={sort} onSort={toggle}>{text(language, "ينتهي", "Expires")}</SortHead>
                  <SortHead id="last" sort={sort} onSort={toggle}>{text(language, "آخر استخدام", "Last used")}</SortHead>
                  <SortHead id="status" sort={sort} onSort={toggle}>{text(language, "الحالة", "Status")}</SortHead>
                  <TableHead className="text-end">{text(language, "إجراء", "Action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((key) => (
                  <TableRow key={key.key_id}>
                    <TableCell className="max-w-[16rem]">
                      <div className="font-medium">{key.name}</div>
                      <Mono>{key.key_id}</Mono>
                    </TableCell>
                    <TableCell>
                      <div className="flex max-w-[16rem] flex-wrap gap-1">
                        {key.scopes.map((scope) => <Badge key={scope} variant="outline" className="font-mono">{scope}</Badge>)}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {key.expires_at ? formatDateTime(key.expires_at, language) : text(language, "لا ينتهي", "Never")}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {key.last_used_at ? formatDateTime(key.last_used_at, language) : text(language, "لم يُستخدم", "Never used")}
                    </TableCell>
                    <TableCell>
                      <StatusBadge tone={key.revoked ? "danger" : "success"}>
                        {key.revoked ? text(language, "ملغى", "Revoked") : text(language, "نشط", "Active")}
                      </StatusBadge>
                    </TableCell>
                    <TableCell className="text-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-danger hover:text-danger"
                        disabled={key.revoked || busy === `key-${key.key_id}`}
                        onClick={() => setRevokeTarget(key)}
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
      </SectionCard>

      <Dialog open={keyFormOpen} onOpenChange={setKeyFormOpen}>
        <DialogContent>
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (keyName.trim() && busy !== "new-key") void makeKey();
            }}
          >
            <DialogHeader>
              <DialogTitle>{text(language, "إنشاء مفتاح API", "Create API key")}</DialogTitle>
              <DialogDescription>{text(language, "اختر اسماً واضحاً ومدة صلاحية مناسبة.", "Choose a descriptive name and a suitable lifetime.")}</DialogDescription>
            </DialogHeader>
            <div className="grid gap-2">
              <Label htmlFor="admin-key-name">{text(language, "اسم المفتاح", "Key name")}</Label>
              <Input
                id="admin-key-name"
                placeholder={text(language, "مثال: مسار CI", "e.g. CI pipeline")}
                value={keyName}
                onChange={(event) => setKeyName(event.target.value)}
                maxLength={120}
                autoFocus
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="admin-key-expiry">{text(language, "مدة الصلاحية", "Lifetime")}</Label>
              <Select value={String(keyExpiryDays)} onValueChange={(value) => setKeyExpiryDays(Number(value))}>
                <SelectTrigger id="admin-key-expiry" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30">{text(language, "ينتهي خلال 30 يوماً", "Expires in 30 days")}</SelectItem>
                  <SelectItem value="90">{text(language, "ينتهي خلال 90 يوماً", "Expires in 90 days")}</SelectItem>
                  <SelectItem value="365">{text(language, "ينتهي خلال سنة", "Expires in 1 year")}</SelectItem>
                  <SelectItem value="0">{text(language, "لا تنتهي صلاحيته", "Never expires")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setKeyFormOpen(false)}>{text(language, "إلغاء", "Cancel")}</Button>
              <Button type="submit" disabled={busy === "new-key" || !keyName.trim()}>
                {busy === "new-key" ? text(language, "جارٍ الإنشاء…", "Creating…") : text(language, "تأكيد", "Confirm")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => { if (!open) setRevokeTarget(null); }}
        title={text(language, "إبطال مفتاح API؟", "Revoke this API key?")}
        description={text(language, `سيتوقف المفتاح «${revokeTarget?.name ?? ""}» عن العمل فوراً ولا يمكن التراجع.`, `The key "${revokeTarget?.name ?? ""}" stops working immediately. This cannot be undone.`)}
        requireText={revokeTarget?.name || revokeTarget?.key_id}
        requireTextLabel={text(language, "اكتب اسم المفتاح للتأكيد:", "Type the key name to confirm:")}
        confirmLabel={text(language, "إبطال المفتاح", "Revoke key")}
        cancelLabel={text(language, "إلغاء", "Cancel")}
        onConfirm={() => { if (revokeTarget) void onRevokeKey(revokeTarget.key_id); }}
      />
    </>
  );
}
