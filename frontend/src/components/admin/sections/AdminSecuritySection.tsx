import { Bot, Settings2, ShieldCheck } from "lucide-react";
import { useLanguage } from "../../../i18n/LanguageContext";
import { adminSectionText as text } from "../sectionText";
import type { AdminPanelSectionModel } from "../AdminPanelSectionModel";
import { AdminAuditCard } from "./AdminAuditCard";
import { PolicyCard } from "../AdminPolicyCard";

export function AdminSecuritySection({ model }: { model: AdminPanelSectionModel }) {
  const { language } = useLanguage();
  const { audit, busy, loading, policies, policy, scan } = model;
  const sec = policies?.security || {};
  const ai = policies?.ai || {};

  return (
    <div className="space-y-6">
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <PolicyCard
          title={text(language, "السياسات الأمنية", "Security policies")}
          icon={Settings2}
          values={sec}
          busy={busy === "security"}
          onToggle={(key, value) => void policy("security", { [key]: value })}
          onSaveValues={(changed) => void policy("security", changed)}
        />

        <PolicyCard
          title={text(language, "حوكمة الفحص", "Scan governance")}
          icon={ShieldCheck}
          values={scan}
          busy={busy === "scan"}
          onToggle={(key, value) => void policy("scan", { [key]: value })}
          onSaveValues={(changed) => void policy("scan", changed)}
        />

        <PolicyCard
          title={text(language, "الذكاء الاصطناعي / Gemini", "AI / Gemini")}
          icon={Bot}
          values={ai}
          busy={busy === "ai"}
          onToggle={(key, value) => void policy("ai", { [key]: value })}
          onSaveValues={(changed) => void policy("ai", changed)}
        />

        <AdminAuditCard audit={audit} loading={loading} />
      </div>
    </div>
  );
}
