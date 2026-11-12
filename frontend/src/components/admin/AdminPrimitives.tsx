import { useEffect, useState, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { Tone } from "./format";

/** Titled card used by every section: icon chip, title, optional description and actions. */
export function SectionCard({
  icon: Icon, title, description, actions, children, className,
}: {
  icon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          {Icon && <Icon className="size-4 text-primary" aria-hidden="true" />}
          {title}
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
        {actions && <CardAction className="flex items-center gap-2">{actions}</CardAction>}
      </CardHeader>
      {children !== undefined && <CardContent className="space-y-4">{children}</CardContent>}
    </Card>
  );
}

export function EmptyState({ icon: Icon = Inbox, children }: { icon?: LucideIcon; children: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-10 text-center">
      <span className="grid size-10 place-items-center rounded-full bg-muted text-muted-foreground">
        <Icon className="size-5" aria-hidden="true" />
      </span>
      <p className="max-w-sm text-sm text-muted-foreground">{children}</p>
    </div>
  );
}

export function RowsSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-11 w-full" />
      ))}
    </div>
  );
}

export function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <Badge variant={tone === "secondary" ? "secondary" : tone}>{children}</Badge>;
}

/** Long identifiers must wrap/truncate instead of widening the layout. */
export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span dir="ltr" className={`block max-w-full truncate font-mono text-xs text-muted-foreground ${className}`} title={typeof children === "string" ? children : undefined}>
      {children}
    </span>
  );
}

/** Destructive-action confirmation (replaces window.confirm); cancel is the default focus. */
export function ConfirmDialog({
  open, onOpenChange, title, description, confirmLabel, cancelLabel, onConfirm, destructive = true,
  requireText, requireTextLabel,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  onConfirm: () => void;
  destructive?: boolean;
  /** Irreversible actions: the confirm button stays disabled until this exact text (case-insensitive) is typed. */
  requireText?: string;
  requireTextLabel?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  useEffect(() => { if (!open) setTyped(""); }, [open]);
  const locked = Boolean(requireText) && typed.trim().toLowerCase() !== (requireText ?? "").trim().toLowerCase();
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription className="break-words">{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {requireText && (
          <div className="flex flex-col gap-2">
            <label htmlFor="confirm-type" className="text-sm text-muted-foreground">{requireTextLabel}</label>
            <Input id="confirm-type" dir="ltr" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={requireText} autoComplete="off" spellCheck={false} />
          </div>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>{cancelLabel}</AlertDialogCancel>
          <AlertDialogAction
            disabled={locked}
            className={destructive ? "bg-destructive text-white hover:bg-destructive/90" : undefined}
            onClick={onConfirm}
          >
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
