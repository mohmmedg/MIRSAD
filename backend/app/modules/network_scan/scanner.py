"""Nmap engine with selectable, auditable scan profiles.

The UI exposes safe, useful profiles rather than arbitrary shell flags. The
profiles cover discovery, TCP/UDP, service/version detection, OS fingerprinting,
NSE default/safe/discovery/vuln checks, full-port scans and a broad maximum
profile. Evasion/spoofing and DoS-style NSE categories are deliberately not
exposed as automatic presets.
"""
import asyncio
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings, verify_target_in_scope, resolve_safe_target
from app.schemas.network import NetworkScanResult, OSMatch, PortInfo, PortState, ScanStatus, ScriptResult

class NmapExecutionError(Exception):
    pass

SCAN_PROFILES: dict[str, dict[str, Any]] = {
    "discovery": {
        "label": "Host discovery", "args": ["-sn", "-PE", "-PP", "-PM", "--reason", "-T4"],
        "description": "اكتشاف حالة المضيف بدون فحص منافذ.",
    },
    "quick": {
        "label": "Quick TCP", "args": ["-sT", "-sV", "--top-ports", "1000", "--reason", "-T4"],
        "description": "TCP + service/version على أهم 1000 منفذ.",
    },
    "balanced": {
        "label": "Balanced", "args": ["-sS", "-sV", "-sC", "--reason", "-T4", "--top-ports", "2000"],
        "description": "TCP + version + default NSE على 2000 منفذ.",
    },
    "comprehensive": {
        "label": "Comprehensive TCP", "args": ["-sS", "-sV", "-sC", "-O", "--reason", "-T4", "-p-"],
        "description": "كل منافذ TCP + version + default scripts + OS detection.",
    },
    "udp": {
        "label": "UDP", "args": ["-sU", "-sV", "--top-ports", "200", "--reason", "-T3"],
        "description": "أهم 200 منفذ UDP مع service detection.",
    },
    "vulnerability": {
        "label": "NSE vulnerability", "args": ["-sS", "-sV", "--script", "vuln", "--reason", "-T3", "--top-ports", "2000"],
        "description": "فحوص NSE المصنفة vuln على 2000 منفذ TCP.",
    },
    "deep": {
        "label": "Deep TCP+UDP", "args": ["-sS", "-sU", "-sV", "-sC", "-O", "--reason", "-T3", "-p", "T:1-65535,U:1-200"],
        "description": "TCP كامل + UDP أهم 200 + version/default scripts/OS.",
    },
    "maximum": {
        "label": "Maximum security audit", "args": ["-sS", "-sU", "-sV", "-sC", "-O", "--script", "default,safe,discovery,vuln", "--reason", "-T3", "-p", "T:1-65535,U:1-200"],
        "description": "تغطية واسعة جداً؛ قد تستغرق وقتاً طويلاً وتولد حركة كثيرة.",
    },
}

class NetworkScanner:
    def __init__(self) -> None:
        self.nmap_binary = settings.NMAP_BINARY_PATH

    async def scan(self, target: str, scan_type: str = "quick", ports: str | None = None, timing: int | None = None) -> NetworkScanResult:
        # nmap argument injection guard: `target` is appended as a single,
        # unquoted argv token to the nmap command line (see _build_command).
        # create_subprocess_exec() prevents *shell* injection, but nmap's own
        # option parser still treats any token beginning with '-' as a flag
        # rather than a target (e.g. "--script=...", "-oG", "-d9", "-6"),
        # which lets a caller who only ever supplied a "target" smuggle in
        # arbitrary nmap options/NSE scripts. Reject that outright.
        if target.strip().startswith("-"):
            raise ValueError("الهدف غير صالح: لا يمكن أن يبدأ بـ '-' (لمنع حقن خيارات nmap).")
        verify_target_in_scope(target)
        if scan_type not in SCAN_PROFILES:
            raise ValueError(f"scan_type غير معروف: '{scan_type}'. القيم: {list(SCAN_PROFILES)}")
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        resolved_target=target
        try:
            resolved_target=resolve_safe_target(target)[0]
        except ValueError:
            # Preserve nmap's own resolution error for invalid/unresolvable hosts.
            resolved_target=target
        command = self._build_command(resolved_target, scan_type, ports, timing)
        try:
            xml_output = await self._run_nmap(command)
            parsed = self._parse_xml(xml_output)
            finished_at = datetime.now(timezone.utc)
            return NetworkScanResult(scan_id=scan_id, target=target, scan_type=scan_type,
                status=ScanStatus.COMPLETED, started_at=started_at, finished_at=finished_at,
                duration_seconds=(finished_at-started_at).total_seconds(), raw_nmap_command=" ".join(command), **parsed)
        except NmapExecutionError as exc:
            finished_at = datetime.now(timezone.utc)
            return NetworkScanResult(scan_id=scan_id, target=target, scan_type=scan_type,
                status=ScanStatus.FAILED, started_at=started_at, finished_at=finished_at,
                duration_seconds=(finished_at-started_at).total_seconds(), error_message=str(exc), raw_nmap_command=" ".join(command))

    def _build_command(self, target: str, scan_type: str, ports: str | None, timing: int | None) -> list[str]:
        args = list(SCAN_PROFILES[scan_type]["args"])
        # User-selectable port range replaces profile port selection, but only
        # as one explicit -p argument; no arbitrary Nmap flags are accepted.
        if ports:
            cleaned = ports.strip()
            if len(cleaned) > 120 or any(ch not in "0123456789,-UT: " for ch in cleaned):
                raise ValueError("صيغة المنافذ غير صالحة. استخدم أمثلة مثل 22,80,443 أو T:1-65535,U:53,161")
            # Remove profile port selectors before adding the custom one.
            out=[]; skip=False
            for i,a in enumerate(args):
                if skip: skip=False; continue
                if a in ("--top-ports", "-p", "-p-"):
                    skip = True
                    continue
                out.append(a)
            args = out + ["-p", cleaned]
        if timing is not None:
            if timing not in range(0,6):
                raise ValueError("timing يجب أن يكون بين 0 و5")
            args = [a for a in args if not (a.startswith("-T") and len(a)==3 and a[2].isdigit())]
            args.append(f"-T{timing}")
        return [self.nmap_binary, *args, "-oX", "-", target]

    async def _run_nmap(self, command: list[str]) -> str:
        try:
            process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError as exc:
            raise NmapExecutionError(f"لم يتم إيجاد nmap binary: {self.nmap_binary}") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=settings.DEFAULT_SCAN_TIMEOUT_SECONDS)
        except asyncio.TimeoutError as exc:
            process.kill(); await process.wait()
            raise NmapExecutionError(f"انتهت مهلة الفحص ({settings.DEFAULT_SCAN_TIMEOUT_SECONDS} ثانية).") from exc
        stderr_text = stderr.decode(errors="ignore").strip()
        if process.returncode != 0:
            raise NmapExecutionError(f"nmap فشل بكود خروج {process.returncode}: {stderr_text}")
        return stdout.decode(errors="ignore")

    @staticmethod
    def _script(elem: ET.Element) -> ScriptResult:
        return ScriptResult(script_id=elem.get("id", "unknown"), output=elem.get("output", "").strip())

    def _parse_xml(self, xml_output: str) -> dict[str, Any]:
        root = ET.fromstring(xml_output)
        host = root.find("host")
        if host is None:
            # حافظ على نفس شكل parsed payload حتى عندما لا يحتوي Nmap على host؛
            # هذا يمنع downstream consumers من التعامل مع شكلين مختلفين للنتيجة.
            return {
                "host_up": False,
                "addresses": [],
                "hostnames": [],
                "open_ports": [],
                "filtered_ports_count": 0,
                "closed_ports_count": 0,
                "os_matches": [],
                "host_scripts": [],
                "traceroute": [],
                "scan_warnings": ["لم يُعثر على host element في XML."],
                "coverage": {"host_discovered": False, "addresses": 0, "hostnames": 0,
                             "open_ports": 0, "filtered_ports": 0, "closed_ports": 0,
                             "os_detection": False, "host_scripts": 0, "port_scripts": 0,
                             "traceroute_hops": 0},
            }
        status = host.find("status")
        host_up = status is not None and status.get("state") == "up"
        addresses = [x.get("addr") for x in host.findall("address") if x.get("addr")]
        hostnames = [x.get("name") for x in host.findall("hostnames/hostname") if x.get("name")]
        open_ports=[]; filtered=closed=0
        ports_elem=host.find("ports")
        if ports_elem is not None:
            for p in ports_elem.findall("port"):
                state=p.find("state"); st=state.get("state") if state is not None else "closed"
                if st=="filtered": filtered+=1
                elif st=="closed": closed+=1
                service=p.find("service")
                scripts=[self._script(s) for s in p.findall("script")]
                cpes=[c.text for c in p.findall("service/cpe") if c.text]
                if st in {"open","open|filtered"}:
                    try: ps=PortState.OPEN
                    except Exception: ps=PortState.FILTERED
                elif st=="filtered": ps=PortState.FILTERED
                else: ps=PortState.CLOSED
                open_ports.append(PortInfo(port=int(p.get("portid","0")), protocol=p.get("protocol","tcp"), state=ps,
                    service_name=service.get("name") if service is not None else None,
                    product=service.get("product") if service is not None else None,
                    version=service.get("version") if service is not None else None,
                    extra_info=service.get("extrainfo") if service is not None else None,
                    cpe=cpes, scripts=scripts))
        os_matches=[]
        for m in host.findall("os/osmatch"):
            try: acc=int(m.get("accuracy","0"))
            except ValueError: acc=0
            os_matches.append(OSMatch(name=m.get("name","unknown"), accuracy=acc))
        host_scripts=[self._script(s) for s in host.findall("hostscript/script")]
        traceroute=[]
        for hop in host.findall("trace/hop"):
            traceroute.append({"ttl": hop.get("ttl"), "ip": hop.get("ipaddr"), "rtt": hop.get("rtt"), "host": hop.get("host")})
        warnings=[]
        if not host_up: warnings.append("المضيف لم يُثبت أنه up؛ بعض النتائج قد تكون ناقصة.")
        coverage={"host_discovered":host_up, "addresses":len(addresses), "hostnames":len(hostnames),
                  "open_ports":sum(1 for p in open_ports if p.state==PortState.OPEN),
                  "filtered_ports":filtered, "closed_ports":closed, "os_detection":bool(os_matches),
                  "host_scripts":len(host_scripts), "port_scripts":sum(len(p.scripts) for p in open_ports),
                  "traceroute_hops":len(traceroute)}
        return {"host_up":host_up,"addresses":addresses,"hostnames":hostnames,"open_ports":open_ports,
                "filtered_ports_count":filtered,"closed_ports_count":closed,"os_matches":os_matches,
                "host_scripts":host_scripts,"traceroute":traceroute,"scan_warnings":warnings,"coverage":coverage}
