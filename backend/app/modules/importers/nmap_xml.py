"""2.5 - Import external scan results: Nmap XML (``nmap -oX``)."""
from __future__ import annotations

from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as DefusedET  # blocks entity expansion / external entities

from app.modules.normalizer.normalizer import make_id
from app.schemas.platform import FindingEvidence, NormalizedFinding


def parse_nmap_xml(xml_bytes: bytes, scan_id: str) -> list[NormalizedFinding]:
    now = datetime.now(timezone.utc)
    try:
        root = DefusedET.fromstring(xml_bytes)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError(f"ملف Nmap XML غير صالح: {exc}") from None

    out: list[NormalizedFinding] = []
    for host in root.iter("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else None
        hostname_el = host.find("hostnames/hostname")
        display_host = (hostname_el.get("name") if hostname_el is not None else None) or host_ip
        if not display_host:
            continue
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") not in ("open", "open|filtered"):
                continue
            portid = port.get("portid", "0")
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            asset = f"{display_host}:{portid}/{protocol}"
            evidence_text = f"{service_name} {product} {version}".strip() or f"open {protocol} port"

            out.append(NormalizedFinding(
                finding_id=make_id("nmap-import", f"open-{portid}-{protocol}", asset, evidence_text),
                scan_id=scan_id,
                source_module="import-nmap",
                title=f"منفذ مفتوح {portid}/{protocol} (مستورد من Nmap)",
                severity="Info",
                confidence=0.9,
                status="OPEN",
                verification_status="DETECTED",
                description="خدمة شبكية مكشوفة مستوردة من مسح Nmap خارجي (-oX)؛ الأهمية الأمنية تعتمد على الخدمة والإصدار.",
                evidence=[FindingEvidence(source="nmap-import", asset=asset, evidence=evidence_text, confidence=0.9)],
                affected_asset=asset,
                tags=["imported", "nmap", "network"] + ([service_name.lower()] if service_name else []),
                first_seen=now,
                last_seen=now,
            ))

            # NSE script output on this port, if present
            for script in port.findall("script"):
                script_id = script.get("id", "")
                script_output = (script.get("output") or "").strip()
                if not script_output:
                    continue
                out.append(NormalizedFinding(
                    finding_id=make_id("nmap-import-nse", script_id, asset, script_output),
                    scan_id=scan_id,
                    source_module="import-nmap",
                    title=f"Nmap NSE: {script_id}",
                    severity="Medium",
                    confidence=0.6,
                    status="OPEN",
                    verification_status="DETECTED",
                    description="مخرجات سكربت Nmap NSE مستوردة (من ملف Nmap XML)؛ تحتاج تحققًا يدويًا.",
                    evidence=[FindingEvidence(source="nmap-import-nse", asset=asset, evidence=script_output[:3000], confidence=0.6)],
                    affected_asset=asset,
                    tags=["imported", "nmap", "nse", "verification-needed"],
                    first_seen=now,
                    last_seen=now,
                ))
    return out
