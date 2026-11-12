import { ComplianceCenter } from "../components/ComplianceCenter";
import { useScan } from "../context/ScanContext";

export function CompliancePage() {
  const { unified } = useScan();
  return (
    <section className="animateIn">
      <ComplianceCenter
        findings={(unified?.findings ?? []) as Array<Record<string, unknown>>}
        coverage={unified?.coverage}
      />
    </section>
  );
}
