from datetime import datetime, timezone

from app.api.routes.assessment import build_attack_surface_graph
from app.schemas.network import NetworkScanResult, PortInfo, PortState, ScanStatus
from app.schemas.platform import UnifiedScanResult


def test_attack_surface_graph_is_built_from_real_snapshot_fields():
    now = datetime.now(timezone.utc)
    scan = UnifiedScanResult(
        scan_id="graph-test",
        target="example.com",
        status="completed",
        started_at=now,
        dns={"addresses": ["93.184.216.34"]},
        tls={"protocol": "TLSv1.3", "subject_alt_names": ["www.example.com"]},
        technologies=["nginx"],
        subdomains=[{"hostname": "api.example.com", "method": "certificate-transparency", "evidence": "SAN"}],
        network_scan=NetworkScanResult(
            scan_id="graph-test", target="example.com", scan_type="quick", status=ScanStatus.COMPLETED,
            started_at=now, open_ports=[PortInfo(port=443, protocol="tcp", state=PortState.OPEN, service_name="https", product="nginx", version="1.25")],
        ),
    )
    graph = build_attack_surface_graph(scan)
    types = {n["type"] for n in graph["nodes"]}
    assert {"domain", "dns", "ip", "certificate", "subdomain", "technology", "port", "service"} <= types
    assert any(e["relation"] == "resolves_to" for e in graph["edges"])
    assert graph["generated_from"] == "persisted_scan_snapshot"
