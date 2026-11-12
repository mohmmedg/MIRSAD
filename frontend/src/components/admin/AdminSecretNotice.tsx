import { useEffect, useState } from "react";
import { Check, Copy, KeyRound, X } from "lucide-react";
import { useLanguage } from "../../i18n/LanguageContext";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { adminSectionText as text } from "./sectionText";

/**
 * One-time reveal for freshly created API keys / generated passwords. The secret lives only in
 * the parent's React state: nothing here writes it to storage, logs or the URL.
 */
export function AdminSecretNotice({ title, secret, onClose }: { title: string; secret: string; onClose: () => void }) {
  const { language } = useLanguage();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  async function copy() {
    try {
      await navigator.clipboard?.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <Alert className="border-warning/40 bg-warning-soft">
      <KeyRound aria-hidden="true" className="text-warning" />
      <AlertTitle className="line-clamp-none text-foreground">{title}</AlertTitle>
      <AlertDescription className="mt-1 gap-3">
        <code dir="ltr" className="block w-full rounded-md border bg-background px-3 py-2 text-start font-mono text-xs break-all text-foreground select-all">
          {secret}
        </code>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => void copy()}>
            {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
            {copied ? text(language, "تم النسخ", "Copied") : text(language, "نسخ", "Copy")}
          </Button>
          <Button size="sm" variant="outline" onClick={onClose}>
            <X aria-hidden="true" />
            {text(language, "إغلاق", "Close")}
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
}
