import React from "react";
import { Boxes, Code2, ServerCog } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats } from "../utils/scanStats";
import { EmptyPageState } from "../components/EmptyPageState";
import { DiscoveryInfoDrawer, type DiscoveryInfo } from "../components/DiscoveryInfoDrawer";
import { PageHeader } from "../components/PageHeader";
import styles from "../components/UnifiedDashboard.module.css";

function assetLabel(asset: Record<string, unknown>): { title: string; meta: string } {
  const type = String(asset.type ?? asset.source ?? "asset");
  const value = String(asset.value ?? asset.target ?? "");
  const extra = [asset.method, asset.service, asset.methods].filter(Boolean).map(String).join(" · ");
  return { title: value || type, meta: [type, extra].filter(Boolean).join(" · ") };
}

// unified.assets ليست قائمة "أصول" منفصلة بالمعنى الشائع (دومين، IP، خدمة كلٌ سطر
// مستقل) — كل عنصر بها سجل واحد مُركّب يحوي بداخله ips/ports/services/endpoints/
// web_apps/apis (راجع backend/app/modules/asset_inventory/inventory.py). عرض
// unified.assets.length وحدها كـ"إجمالي الأصول" كان يُظهر 1 دائماً تقريباً حتى لو
// اكتُشف عشرات الـIPs/المنافذ/النقاط، وهو رقم مضلِّل. هذه الدالة تستخرج البنود
// الفعلية من داخل كل سجل حتى نعرض عدداً له معنى حقيقي، وقائمة تفصيلية بدل صف واحد فارغ الدلالة.
function surfaceCounts(asset: Record<string, unknown>) {
  const arr = (key: string): unknown[] => (Array.isArray(asset[key]) ? (asset[key] as unknown[]) : []);
  return {
    ips: arr("ips"),
    ports: arr("ports"),
    services: arr("services"),
    endpoints: arr("endpoints"),
    webApps: arr("web_apps"),
    apis: arr("apis"),
  };
}

function itemLabel(item: unknown): string {
  if (item && typeof item === "object") {
    const obj = item as Record<string, unknown>;
    return String(obj.name ?? obj.value ?? obj.url ?? obj.service ?? obj.port ?? JSON.stringify(obj));
  }
  return String(item);
}

export function AssetsPage() {
  const { language, strings } = useLanguage();
  const { unified } = useScan();
  const stats = useDerivedScanStats(unified);
  const [selectedDiscovery, setSelectedDiscovery] = React.useState<DiscoveryInfo | null>(null);
  const m = strings.unified;

  if (!unified) {
    return (
      <EmptyPageState
        title={language === "ar" ? "لا توجد أصول بعد" : "No assets yet"}
        description={
          language === "ar"
            ? "شغّل فحصاً لاكتشاف التقنيات، عناوين IP، ونقاط نهاية JavaScript."
            : "Run a scan to discover technologies, IP addresses and JavaScript endpoints."
        }
      />
    );
  }

  const surfaceTotal = unified.assets.reduce((sum, asset) => {
    const c = surfaceCounts(asset);
    return sum + c.ips.length + c.ports.length + c.services.length + c.endpoints.length + c.webApps.length + c.apis.length;
  }, 0);

  return (
    <section className="animateIn">
      <PageHeader icon={Boxes} eyebrow={language === "ar" ? "الأصول" : "ASSETS"} title={language === "ar" ? "الأصول والتقنيات" : "Assets & technology"} description={<span className="ltr">{unified.target}</span>} />

      <div className={styles.metricGrid}>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "سجلات الأصول" : "Asset records"}</span>
          <strong className={styles.metricValue}>{unified.assets.length}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "بنود سطح الهجوم" : "Surface items"}</span>
          <strong className={styles.metricValue}>{surfaceTotal}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "التقنيات" : "Technologies"}</span>
          <strong className={styles.metricValue}>{unified.technologies.length}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "عناوين IP" : "IP addresses"}</span>
          <strong className={styles.metricValue}>{stats.dnsAddresses.length}</strong>
        </div>
        <div className={styles.metricCard}>
          <span className={styles.metricLabel}>{language === "ar" ? "نقاط نهاية JS" : "JS endpoints"}</span>
          <strong className={styles.metricValue}>{stats.jsEndpoints}</strong>
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Boxes size={15} />
          <span>{language === "ar" ? "التقنيات المكتشفة" : "Detected technologies"}</span>
        </div>
        <div className={styles.chipCloud}>
          {unified.technologies.length ? (
            unified.technologies.map((technology) => (
              <button key={technology} className={`${styles.chip} ltr`} onClick={() => setSelectedDiscovery({
                type: language === "ar" ? "تقنية" : "Technology", value: technology,
                method: "Fingerprinting", source: "MIRSAD technology fingerprint engine",
                evidence: `Technology signature matched: ${technology}`,
                explanation: language === "ar" ? "تمت مطابقة بصمات من ترويسة الخادم أو روابط/ملفات JavaScript أو معلومات الخدمات الشبكية." : "Matched signatures from server headers, URLs/JavaScript assets, or network service fingerprints."
              })}>{technology}</button>
            ))
          ) : (
            <span className={styles.muted}>{m.noneLabel}</span>
          )}
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Boxes size={15} />
          <span>{language === "ar" ? "عناوين IP" : "IP addresses"}</span>
        </div>
        <div className={styles.chipCloud}>
          {stats.dnsAddresses.length ? (
            stats.dnsAddresses.map((ip) => (
              <button key={ip} className={`${styles.chip} ${styles.ipChip} ltr`} onClick={() => setSelectedDiscovery({
                type: "IP", value: ip, method: "DNS resolution", source: "MIRSAD DNS snapshot",
                evidence: `Resolved address: ${ip}`,
                explanation: language === "ar" ? "تم حل اسم النطاق إلى عنوان IP عبر استعلامات DNS للنظام." : "The target hostname was resolved to this IP using DNS resolution."
              })}>{ip}</button>
            ))
          ) : (
            <span className={styles.muted}>{m.noneLabel}</span>
          )}
        </div>
      </div>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <ServerCog size={15} />
          <span>{language === "ar" ? "سجلات الأصول" : "Asset records"}</span>
          <span className={styles.cardMeta}>{unified.assets.length}</span>
        </div>
        <p className={styles.subtitle} style={{ margin: "0 0 12px" }}>
          {language === "ar"
            ? "كل سجل يمثّل هدفاً واحداً ويحوي بداخله كل ما اكتُشف عنه (IPs، منافذ، خدمات، نقاط نهاية، تطبيقات API)."
            : "Each record represents one target and bundles everything discovered about it (IPs, ports, services, endpoints, API apps)."}
        </p>
        {unified.assets.length ? (
          <div className={styles.findingList}>
            {unified.assets.map((asset, index) => {
              const { title, meta } = assetLabel(asset);
              const c = surfaceCounts(asset);
              const groups: Array<[string, unknown[]]> = [
                [language === "ar" ? "IPs" : "IPs", c.ips],
                [language === "ar" ? "المنافذ" : "Ports", c.ports],
                [language === "ar" ? "الخدمات" : "Services", c.services],
                [language === "ar" ? "نقاط النهاية" : "Endpoints", c.endpoints],
                [language === "ar" ? "تطبيقات ويب" : "Web apps", c.webApps],
                [language === "ar" ? "APIs" : "APIs", c.apis],
              ];
              return (
                <div key={`${title}-${index}`} className={styles.findingRow} style={{ cursor: "pointer", flexDirection: "column", alignItems: "stretch" }}
                  onClick={() => setSelectedDiscovery({
                    type: language === "ar" ? "أصل" : "Asset", value: title,
                    method: "Asset inventory correlation", source: "MIRSAD asset inventory",
                    evidence: `Asset ID: ${String(asset.asset_id ?? "n/a")}`,
                    explanation: language === "ar" ? "تم إنشاء الأصل من نتائج DNS/الشبكة/الويب ودمج مكوناته في سجل واحد." : "The asset was built by correlating DNS, network and web observations into one inventory record."
                  })}>
                  <div className={styles.findingBody}>
                    <div className={`${styles.findingTitle} ltr`}>{title}</div>
                    {meta && <div className={styles.findingAsset}>{meta}</div>}
                  </div>
                  <div className={styles.chipCloud} style={{ marginTop: 8 }}>
                    {groups
                      .filter(([, items]) => items.length > 0)
                      .map(([label, items]) => (
                        <span key={label} className={styles.chip} title={items.map(itemLabel).join(", ")}>
                          {label}: {items.length}
                        </span>
                      ))}
                    {groups.every(([, items]) => items.length === 0) && (
                      <span className={styles.muted}>{m.noneLabel}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <span className={styles.muted}>{m.noneLabel}</span>
        )}
      </div>

      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <Code2 size={15} />
          <span>{language === "ar" ? "نقاط نهاية الويب المكتشفة" : "Discovered web endpoints"}</span>
          <span className={styles.cardMeta}>{unified.web_scan?.endpoints?.length ?? 0}</span>
        </div>
        {unified.web_scan?.endpoints?.length ? (
          <div className={styles.findingList}>
            {unified.web_scan.endpoints.map((endpoint, index) => (
              <div key={`${endpoint.url}-${index}`} className={styles.findingRow} style={{ cursor: "pointer" }} onClick={() => setSelectedDiscovery({
                  type: language === "ar" ? "نقطة نهاية" : "Endpoint", value: endpoint.url,
                  method: endpoint.source || "Web crawler", source: endpoint.source || "MIRSAD web scanner",
                  evidence: `HTTP ${endpoint.status_code ?? "?"} · ${endpoint.content_type ?? "unknown content type"}`,
                  explanation: language === "ar" ? "تم الوصول إلى الرابط أثناء الزحف، ثم تسجيله كنقطة نهاية." : "The URL was reached during crawling and recorded as a web endpoint."
                })}>
                <span className={`${styles.findingSev} ${styles.info}`}>{endpoint.method}</span>
                <div className={styles.findingBody}>
                  <div className={`${styles.findingTitle} ltr`}>{endpoint.url}</div>
                  <div className={styles.findingAsset}>
                    {[endpoint.source, endpoint.status_code, endpoint.content_type].filter(Boolean).join(" · ")}
                    {endpoint.parameters?.length
                      ? ` · ${language === "ar" ? "معاملات" : "params"}: ${endpoint.parameters.join(", ")}`
                      : ""}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <span className={styles.muted}>{m.noneLabel}</span>
        )}
      </div>

      {unified.subdomains?.length > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}><Boxes size={15} /><span>{language === "ar" ? "النطاقات الفرعية المكتشفة" : "Discovered subdomains"}</span><span className={styles.cardMeta}>{unified.subdomains.length}</span></div>
          <div className={styles.chipCloud}>
            {unified.subdomains.map((s) => (
              <button key={s.hostname} className={`${styles.chip} ltr`} onClick={() => setSelectedDiscovery({
                type: language === "ar" ? "نطاق فرعي" : "Subdomain", value: s.hostname, method: s.method,
                source: s.source, evidence: s.evidence, command: s.source === "Nmap" ? (unified.network_scan?.raw_nmap_command ?? undefined) : undefined,
                explanation: language === "ar" ? "تم الاحتفاظ به لأنه يقع ضمن النطاق الأساسي المطلوب فحصه." : "Retained because it belongs to the requested in-scope base domain."
              })}>{s.hostname}</button>
            ))}
          </div>
        </div>
      )}

      {(unified.web_scan?.javascript_assets?.length ?? 0) > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Code2 size={15} />
            <span>{language === "ar" ? "ملفات JavaScript المكتشفة" : "Discovered JavaScript assets"}</span>
            <span className={styles.cardMeta}>{unified.web_scan?.javascript_assets.length}</span>
          </div>
          <div className={styles.chipCloud}>
            {unified.web_scan?.javascript_assets.map((asset) => (
              <button key={asset} className={`${styles.chip} ltr`} onClick={() => setSelectedDiscovery({
                  type: language === "ar" ? "ملف JavaScript" : "JavaScript asset", value: asset,
                  method: "HTML/JavaScript asset extraction", source: "MIRSAD web crawler",
                  evidence: asset,
                  explanation: language === "ar" ? "تم استخراج رابط ملف JavaScript من خصائص src في HTML أو أثناء تحليل الصفحة." : "The JavaScript URL was extracted from HTML src attributes or page analysis."
                })}>{asset}</button>
            ))}
          </div>
        </div>
      )}
      {selectedDiscovery && <DiscoveryInfoDrawer item={selectedDiscovery} onClose={() => setSelectedDiscovery(null)} />}
    </section>
  );
}
