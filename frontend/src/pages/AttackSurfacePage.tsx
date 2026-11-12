import React from "react";
import { Boxes, Code2, Globe, Lock, Network, Waypoints } from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats } from "../utils/scanStats";
import { EmptyPageState } from "../components/EmptyPageState";
import { PageHeader } from "../components/PageHeader";
import styles from "../components/UnifiedDashboard.module.css";
import { DiscoveryInfoDrawer, type DiscoveryInfo } from "../components/DiscoveryInfoDrawer";

export function AttackSurfacePage() {
  const { language } = useLanguage();
  const { unified } = useScan();
  const stats = useDerivedScanStats(unified);
  const [selectedDiscovery, setSelectedDiscovery] = React.useState<DiscoveryInfo | null>(null);

  if (!unified) {
    return (
      <EmptyPageState
        title={language === "ar" ? "لا يوجد سطح هجوم بعد" : "No attack surface yet"}
        description={
          language === "ar"
            ? "شغّل فحصاً كاملاً لبناء خريطة سطح الهجوم من النطاق والخدمات ونقاط النهاية."
            : "Run a full scan to build the attack surface map from the domain, services and endpoints."
        }
      />
    );
  }

  return (
    <section className="animateIn">
      <PageHeader icon={Waypoints} eyebrow={language === "ar" ? "سطح الهجوم" : "ATTACK SURFACE"} title={language === "ar" ? "اكتشافات مترابطة" : "Correlated discovery"} description={<span className="ltr">{unified.target}</span>} />

      <div className={styles.card}>
        <div className={styles.surface}>
          <div className={styles.surfaceNode}>
            <Globe size={18} />
            <b className="ltr">{unified.target}</b>
            <small>DOMAIN</small>
          </div>
          <div className={styles.surfaceLine} />
          <div className={styles.surfaceBranch}>
            <div className={styles.surfaceNode}>
              <Network size={16} />
              <b>{stats.dnsAddresses.length}</b>
              <small>IPs</small>
            </div>
            <div className={styles.surfaceNode}>
              <Lock size={16} />
              <b>{stats.services}</b>
              <small>SERVICES</small>
            </div>
            <div className={styles.surfaceNode}>
              <Code2 size={16} />
              <b>{stats.totalEndpoints}</b>
              <small>ENDPOINTS</small>
            </div>
            <div className={styles.surfaceNode}>
              <Boxes size={16} />
              <b>{unified.technologies.length}</b>
              <small>TECHNOLOGIES</small>
            </div>
          </div>
        </div>
      </div>

      {stats.dnsAddresses.length > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Network size={15} />
            <span>{language === "ar" ? "عناوين IP المكتشفة" : "Discovered IP addresses"}</span>
          </div>
          <div className={styles.chipCloud}>
            {stats.dnsAddresses.map((ip) => (
              <button key={ip} className={`${styles.chip} ${styles.ipChip} ltr`} onClick={() => setSelectedDiscovery({
                type: "IP", value: ip, method: "DNS resolution", source: "MIRSAD DNS snapshot",
                evidence: `Resolved address: ${ip}`
              })}>{ip}</button>
            ))}
          </div>
        </div>
      )}

      {unified.subdomains?.length > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}><Globe size={15} /><span>{language === "ar" ? "النطاقات الفرعية" : "Subdomains"}</span><span className={styles.cardMeta}>{unified.subdomains.length}</span></div>
          <div className={styles.chipCloud}>
            {unified.subdomains.map((s) => <button key={s.hostname} className={`${styles.chip} ltr`} onClick={() => setSelectedDiscovery({
              type: "Subdomain", value: s.hostname, method: s.method, source: s.source, evidence: s.evidence, command: s.source === "Nmap" ? (unified.network_scan?.raw_nmap_command ?? undefined) : undefined
            })}>{s.hostname}</button>)}
          </div>
        </div>
      )}

      {unified.assessment_intelligence && (
        <div className={styles.card}>
          <div className={styles.cardHeader}><Waypoints size={15} /><span>{language === "ar" ? "ذكاء التقييم" : "Assessment intelligence"}</span></div>
          <div className={styles.surfaceBranch}>
            <div className={styles.surfaceNode}><Code2 size={15} /><b>{Number(unified.assessment_intelligence.endpoint_count ?? 0)}</b><small>ENDPOINTS</small></div>
            <div className={styles.surfaceNode}><Network size={15} /><b>{Object.keys((unified.assessment_intelligence.parameter_class_counts as Record<string, unknown>) ?? {}).length}</b><small>PARAMETER CLASSES</small></div>
            <div className={styles.surfaceNode}><Boxes size={15} /><b>{Array.isArray(unified.assessment_intelligence.attack_chain_hints) ? unified.assessment_intelligence.attack_chain_hints.length : 0}</b><small>ATTACK CHAINS</small></div>
          </div>
        </div>
      )}

      {(unified.subdomain_scans?.length ?? 0) > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}><Globe size={15} /><span>{language === "ar" ? "تقييم النطاقات الفرعية" : "Subdomain assessment"}</span><span className={styles.cardMeta}>{unified.subdomain_scans?.length}</span></div>
          <div className={styles.findingList}>
            {unified.subdomain_scans?.map((s, index) => {
              const host = String(s.hostname ?? s.target ?? "unknown");
              const status = String(s.status ?? "UNKNOWN");
              const count = Number(s.findings_count ?? 0);
              return (
                <div key={`${host}-${index}`} className={styles.findingRow}>
                  <span className={`${styles.findingSev} ${status === "SCANNED" ? styles.info : styles.low}`}>{status}</span>
                  <div className={styles.findingBody}>
                    <div className={`${styles.findingTitle} ltr`}>{host}</div>
                    <div className={styles.findingAsset}>{count} findings{String(s.reason ?? "") ? ` · ${String(s.reason)}` : ""}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {(unified.network_scan?.open_ports?.length ?? 0) > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Lock size={15} />
            <span>{language === "ar" ? "الخدمات المكتشفة" : "Discovered services"}</span>
            <span className={styles.cardMeta}>{unified.network_scan?.open_ports.length}</span>
          </div>
          <div className={styles.findingList}>
            {unified.network_scan?.open_ports.map((port, index) => (
              <div key={`${port.port}-${port.protocol}-${index}`} className={styles.findingRow} style={{ cursor: "pointer" }} onClick={() => setSelectedDiscovery({
                  type: language === "ar" ? "خدمة/منفذ" : "Service/Port", value: `${port.port}/${port.protocol}`,
                  method: "Nmap service/version detection", source: "Nmap",
                  command: unified.network_scan?.raw_nmap_command ?? undefined,
                  evidence: `${port.service_name ?? "unknown"} ${port.product ?? ""} ${port.version ?? ""}`.trim(),
                  explanation: language === "ar" ? "تم اكتشاف المنفذ والخدمة من نتيجة Nmap للفحص الشبكي. ظهور المنفذ لا يعني وجود ثغرة؛ يلزم التحقق من الخدمة والإصدار والإعدادات." : "The port and service were identified from the Nmap network scan. An open port alone does not prove a vulnerability; service, version and configuration require validation.",
                  exploitability: language === "ar" ? "قد يصبح الاستغلال ممكناً فقط إذا كانت الخدمة المكشوفة تحتوي على ضعف معروف أو إعداد غير آمن أو خدمة قابلة للوصول دون حماية مناسبة." : "Exploitation is only plausible if the exposed service has a known weakness, unsafe configuration, or an otherwise exploitable exposure."
                })}>
                <span className={`${styles.findingSev} ${styles.info}`}>
                  {port.port}/{port.protocol}
                </span>
                <div className={styles.findingBody}>
                  <div className={`${styles.findingTitle} ltr`}>
                    {[port.service_name, port.product, port.version].filter(Boolean).join(" ") ||
                      (language === "ar" ? "خدمة غير معروفة" : "Unknown service")}
                  </div>
                  <div className={styles.findingAsset}>{port.state}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {(unified.web_scan?.endpoints?.length ?? 0) > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Code2 size={15} />
            <span>{language === "ar" ? "نقاط النهاية المكتشفة" : "Discovered endpoints"}</span>
            <span className={styles.cardMeta}>{unified.web_scan?.endpoints.length}</span>
          </div>
          <div className={styles.findingList}>
            {unified.web_scan?.endpoints.map((endpoint, index) => (
              <div key={`${endpoint.url}-${index}`} className={styles.findingRow} style={{ cursor: "pointer" }} onClick={() => setSelectedDiscovery({
                  type: language === "ar" ? "نقطة نهاية" : "Endpoint", value: endpoint.url,
                  method: "Web crawler", source: "MIRSAD web scanner",
                  evidence: `HTTP ${endpoint.status_code ?? "?"}`
                })}>
                <span className={`${styles.findingSev} ${styles.info}`}>{endpoint.method}</span>
                <div className={styles.findingBody}>
                  <div className={`${styles.findingTitle} ltr`}>{endpoint.url}</div>
                  {endpoint.status_code != null && (
                    <div className={styles.findingAsset}>HTTP {endpoint.status_code}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {(unified.api_scan?.endpoints?.length ?? 0) > 0 && (
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Waypoints size={15} />
            <span>{language === "ar" ? "نقاط نهاية API" : "API endpoints"}</span>
            <span className={styles.cardMeta}>{unified.api_scan?.endpoints.length}</span>
          </div>
          <div className={styles.findingList}>
            {unified.api_scan?.endpoints.map((endpoint, index) => (
              <div key={`${endpoint.url}-${index}`} className={styles.findingRow} style={{ cursor: "pointer" }} onClick={() => setSelectedDiscovery({
                  type: language === "ar" ? "نقطة نهاية" : "Endpoint", value: endpoint.url,
                  method: "Web crawler", source: "MIRSAD web scanner",
                  evidence: `HTTP ${endpoint.observations?.[0]?.status_code ?? "?"}`
                })}>
                <span className={`${styles.findingSev} ${styles.info}`}>{endpoint.methods.join(",")}</span>
                <div className={styles.findingBody}>
                  <div className={`${styles.findingTitle} ltr`}>{endpoint.path}</div>
                  <div className={styles.findingAsset}>{endpoint.source}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {selectedDiscovery && <DiscoveryInfoDrawer item={selectedDiscovery} onClose={() => setSelectedDiscovery(null)} />}
    </section>
  );
}