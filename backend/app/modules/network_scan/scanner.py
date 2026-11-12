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

import logging as _logging
logger = _logging.getLogger(__name__)

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
        "label": "Maximum security audit", "args": ["-sS", "-sU", "-sV", "-sC", "-O", "--script", "default,safe,discovery,vuln", "--reason", "-T3", "-p", "T:1-65535,U:1-65535"],
        "description": "TCP وUDP كاملان 1-65535؛ قد يستغرق وقتاً طويلاً جداً وتولد حركة كثيرة.",
    },
}

TWO_PHASE_PROFILES = {"comprehensive", "deep", "maximum"}

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

        # The scanner runs inside Docker. A user entering localhost/127.0.0.1
        # normally means the host machine from the operator's browser, while
        # Nmap would otherwise scan the backend container's own loopback.
        # Match the web engine's Docker-host translation so network and web
        # modules test the same target. This is only for loopback input.
        if str(resolved_target).lower() in {"127.0.0.1", "localhost", "::1"}:
            resolved_target = "host.docker.internal"

        command = self._build_command(resolved_target, scan_type, ports, timing)
        local_target = str(resolved_target).lower() in {"host.docker.internal", "127.0.0.1", "localhost", "::1"}
        try:
            if scan_type in TWO_PHASE_PROFILES and getattr(settings, "NMAP_TWO_PHASE", True):
                parsed, command_text = await self._scan_two_phase(command, local_target)
                finished_at = datetime.now(timezone.utc)
                return NetworkScanResult(scan_id=scan_id, target=target, scan_type=scan_type,
                    status=ScanStatus.COMPLETED, started_at=started_at, finished_at=finished_at,
                    duration_seconds=(finished_at-started_at).total_seconds(), raw_nmap_command=command_text, **parsed)
            if local_target:
                command = self._harden_for_docker_host(command)
            xml_output, command, fallback_warning = await self._run_with_fallback(command)
            parsed = self._parse_xml(xml_output)
            if fallback_warning:
                parsed["scan_warnings"] = list(parsed.get("scan_warnings") or []) + [fallback_warning]
            finished_at = datetime.now(timezone.utc)
            return NetworkScanResult(scan_id=scan_id, target=target, scan_type=scan_type,
                status=ScanStatus.COMPLETED, started_at=started_at, finished_at=finished_at,
                duration_seconds=(finished_at-started_at).total_seconds(), raw_nmap_command=" ".join(command), **parsed)
        except NmapExecutionError as exc:
            finished_at = datetime.now(timezone.utc)
            return NetworkScanResult(scan_id=scan_id, target=target, scan_type=scan_type,
                status=ScanStatus.FAILED, started_at=started_at, finished_at=finished_at,
                duration_seconds=(finished_at-started_at).total_seconds(), error_message=str(exc), raw_nmap_command=" ".join(command))


    async def _run_with_fallback(self, command: list[str]) -> tuple[str, list[str], str | None]:
        """Run nmap; if raw sockets are unavailable fall back to a connect scan."""
        try:
            return await self._run_nmap(command), command, None
        except NmapExecutionError as priv_exc:
            _msg = str(priv_exc).lower()
            # Any "no raw-socket privilege" failure falls back to a connect scan:
            # nmap says "requires root privileges" when it is unprivileged, and
            # "couldn't open a raw socket / operation not permitted / dnet" when
            # NMAP_PRIVILEGED is set but the capabilities are missing at runtime.
            if not any(m in _msg for m in ("root privileges", "raw socket", "operation not permitted", "dnet:", "failed to open device")):
                raise
            # The container runs as a non-root user (and no-new-privileges blocks file
            # capabilities), so raw-socket scans (-sS/-sU/-O) are impossible. Fall back to a
            # TCP connect scan instead of failing the whole module, and say so explicitly.
            command = self._unprivileged_command(command)
            xml_output = await self._run_nmap(command)
            return xml_output, command, ("nmap has no raw-socket privileges: ran a TCP connect scan (-sT) without UDP (-sU) "
                                         "and OS detection (-O). Run the backend with NET_RAW and without no-new-privileges for the full scan.")

    @staticmethod
    def _split_port_args(args: list[str]) -> tuple[list[str], list[str], list[str]]:
        """Return (args_without_port_selection, tcp_port_args, udp_port_args)."""
        rest: list[str] = []
        tcp: list[str] = []
        udp: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-p-":
                tcp, udp = ["-p", "1-65535"], ["-p", "1-65535"]
            elif a == "--top-ports" and i + 1 < len(args):
                tcp, udp = ["--top-ports", args[i + 1]], ["--top-ports", args[i + 1]]
                i += 1
            elif a == "-p" and i + 1 < len(args):
                t_parts: list[str] = []; u_parts: list[str] = []; cur = None
                for tok in args[i + 1].split(","):
                    tok = tok.strip()
                    if not tok:
                        continue
                    if tok[:2] in ("T:", "U:"):
                        cur = tok[0]; tok = tok[2:]
                    if cur in (None, "T"):
                        t_parts.append(tok)
                    if cur in (None, "U"):
                        u_parts.append(tok)
                tcp = ["-p", ",".join(t_parts)] if t_parts else []
                udp = ["-p", ",".join(u_parts)] if u_parts else []
                i += 1
            else:
                rest.append(a)
            i += 1
        return rest, tcp, udp

    @staticmethod
    def _drop(args: list[str], flags: set[str], with_value: set[str] = frozenset()) -> list[str]:
        out: list[str] = []; skip = False
        for a in args:
            if skip:
                skip = False; continue
            if a in flags:
                continue
            if a in with_value:
                skip = True; continue
            if any(a.startswith(v + "=") for v in with_value):
                continue
            out.append(a)
        return out

    def _two_phase_commands(self, command: list[str]) -> tuple[list[str], str, list[str] | None]:
        """Build (tcp_discovery_cmd, tcp_detail_template, udp_cmd|None) from a full profile command.

        The detail command is returned as a list with a ``@PORTS@`` placeholder.
        """
        binary, tail = command[0], command[-3:]          # tail == ["-oX", "-", target]
        args, tcp_ports, udp_ports = self._split_port_args(command[1:-3])
        has_udp = "-sU" in args
        base = [a for a in args if a != "-sU"]
        tech = "-sT" if "-sT" in base else "-sS"
        # Phase 1: port discovery only (no -sV/-sC/-O/NSE), fast rate.
        p1 = self._drop(base, {"-sV", "-sC", "-O", "--osscan-guess", "--osscan-limit"}, {"--script"})
        if tech not in p1:
            p1.append(tech)
        # No --max-retries cap: default retransmissions keep discovery reliable (a port missed
        # here is never examined by phase 2), so completeness wins over a little extra speed.
        p1 += ["--min-rate", str(int(getattr(settings, "NMAP_DISCOVERY_MIN_RATE", 500)))]
        p1 = [binary, *p1, *tcp_ports, *tail]
        # Phase 2: the full original TCP options, but only on ports found open.
        p2 = [binary, *base, "-p", "@PORTS@", *tail]
        udp_cmd = None
        if has_udp:
            # UDP keeps version detection AND the profile's NSE options (-sC/--script);
            # only TCP-specific flags are removed. Default retries are kept.
            u = self._drop(args, {"-sS", "-sT", "-O", "--osscan-guess", "--osscan-limit"})
            if "-sV" not in u:
                u.append("-sV")
            # UDP is rate-limited by ICMP, so a full 1-65535 range takes hours/days
            # (nmap docs: scan fewer ports; keep UDP separate from TCP). Clamp it to the
            # most common UDP ports and bound retries/host time so it can never hold the
            # whole network stage hostage. TCP keeps the full range.
            udp_ports = self._clamp_udp_ports(udp_ports)
            u = self._drop(u, set(), {"--max-retries", "--host-timeout"})
            u += ["--max-retries", str(int(getattr(settings, "NMAP_UDP_MAX_RETRIES", 1))),
                  "--host-timeout", f"{int(getattr(settings, 'NMAP_UDP_HOST_TIMEOUT_SECONDS', 600))}s"]
            udp_cmd = [binary, *u, *udp_ports, *tail]
        return p1, p2, udp_cmd

    @staticmethod
    def _clamp_udp_ports(udp_ports: list[str]) -> list[str]:
        """Replace huge UDP port selections with --top-ports N (N = NMAP_UDP_TOP_PORTS)."""
        top_n = max(1, int(getattr(settings, "NMAP_UDP_TOP_PORTS", 200)))
        if not udp_ports:
            return ["--top-ports", str(top_n)]
        if udp_ports[0] == "--top-ports":
            try:
                return ["--top-ports", str(min(int(udp_ports[1]), top_n))]
            except (IndexError, ValueError):
                return ["--top-ports", str(top_n)]
        if udp_ports[0] == "-p" and len(udp_ports) > 1:
            total = 0
            for part in udp_ports[1].split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        lo, hi = part.split("-", 1)
                        total += int(hi or 65535) - int(lo or 1) + 1
                    except ValueError:
                        total += top_n + 1
                elif part:
                    total += 1
            if total > top_n:
                return ["--top-ports", str(top_n)]
        return udp_ports

    @staticmethod
    def _merge_parsed(tcp1: dict, tcp2: dict | None, udp: dict | None, notes: list[str]) -> dict[str, Any]:
        detail = tcp2 or tcp1
        ports = list(detail["open_ports"]) + (list(udp["open_ports"]) if udp else [])
        filtered = tcp1["filtered_ports_count"] + (udp["filtered_ports_count"] if udp else 0)
        closed = tcp1["closed_ports_count"] + (udp["closed_ports_count"] if udp else 0)
        addresses = list(dict.fromkeys([*detail["addresses"], *tcp1["addresses"]]))
        hostnames = list(dict.fromkeys([*detail["hostnames"], *tcp1["hostnames"]]))
        warnings = list(dict.fromkeys([*tcp1["scan_warnings"], *detail["scan_warnings"], *((udp or {}).get("scan_warnings") or []), *notes]))
        host_up = tcp1["host_up"] or bool(udp and udp["host_up"])
        coverage = {"host_discovered": host_up, "hosts": tcp1["host_count"], "addresses": len(addresses), "hostnames": len(hostnames),
                    "open_ports": sum(1 for p in ports if p.state == PortState.OPEN),
                    "filtered_ports": filtered, "closed_ports": closed, "os_detection": bool(detail["os_matches"]),
                    "host_scripts": len(detail["host_scripts"]), "port_scripts": sum(len(p.scripts) for p in ports),
                    "traceroute_hops": len(detail["traceroute"])}
        return {"host_up": host_up, "host_count": tcp1["host_count"], "addresses": addresses, "hostnames": hostnames,
                "open_ports": ports, "filtered_ports_count": filtered, "closed_ports_count": closed,
                "os_matches": detail["os_matches"], "host_scripts": detail["host_scripts"], "traceroute": detail["traceroute"],
                "scan_warnings": warnings, "coverage": coverage}

    async def _scan_two_phase(self, command: list[str], local_target: bool) -> tuple[dict[str, Any], str]:
        """Fast TCP discovery -> detailed scan on open ports only; UDP runs in parallel."""
        p1, p2_tpl, udp_cmd = self._two_phase_commands(command)
        hard = self._harden_for_docker_host if local_target else (lambda c: c)
        notes: list[str] = []
        used: list[str] = []

        async def tcp_chain() -> tuple[dict, dict | None]:
            c1 = hard(p1)
            xml1, c1, warn1 = await self._run_with_fallback(c1)
            used.append(" ".join(c1))
            if warn1: notes.append(warn1)
            parsed1 = self._parse_xml(xml1)
            open_tcp = sorted({p.port for p in parsed1["open_ports"] if p.protocol == "tcp" and p.state == PortState.OPEN})
            if not open_tcp:
                notes.append("Two-phase scan: no open TCP ports found, detailed (-sV/-sC/-O) phase skipped.")
                return parsed1, None
            # nmap's OS detection (-O) needs at least one OPEN and one CLOSED TCP port. Limiting -p to the
            # open ports alone would remove every closed port and degrade OS fingerprinting, so a
            # normally-closed probe port (1) is added to the list.
            detail_ports = sorted(set(open_tcp) | {1})
            c2 = hard([",".join(map(str, detail_ports)) if a == "@PORTS@" else a for a in p2_tpl])
            xml2, c2, warn2 = await self._run_with_fallback(c2)
            used.append(" ".join(c2))
            if warn2: notes.append(warn2)
            return parsed1, self._parse_xml(xml2)

        async def udp_chain() -> dict | None:
            if udp_cmd is None:
                return None
            udp_cap = max(60, int(getattr(settings, "NMAP_UDP_TIMEOUT_SECONDS", 900)))
            try:
                xml_u, cu, warn_u = await asyncio.wait_for(self._run_with_fallback(hard(udp_cmd)), timeout=udp_cap)
            except asyncio.TimeoutError:
                # The cancelled nmap child is killed by _run_nmap; TCP results are kept.
                notes.append(f"UDP phase stopped after {udp_cap}s (UDP is rate-limited); TCP results are complete.")
                return None
            except NmapExecutionError as exc:
                notes.append(f"UDP phase failed: {str(exc)[:200]}")
                return None
            used.append(" ".join(cu))
            if warn_u: notes.append(warn_u)
            return self._parse_xml(xml_u)

        (tcp1, tcp2), udp = await asyncio.gather(tcp_chain(), udp_chain())
        if udp_cmd is not None and udp is None and not any("UDP phase" in n for n in notes):
            notes.append("UDP phase produced no result (unprivileged fallback skips UDP).")
        notes.append("Two-phase nmap: TCP discovery then detailed scan on open ports.")
        return self._merge_parsed(tcp1, tcp2, udp, notes), " ; ".join(used)

    def _build_command(self, target: str, scan_type: str, ports: str | None, timing: int | None) -> list[str]:
        args = list(SCAN_PROFILES[scan_type]["args"])
        # User-selectable port range replaces profile port selection, but only
        # as one explicit -p argument; no arbitrary Nmap flags are accepted.
        if ports:
            cleaned = ports.strip()
            if cleaned.lower().startswith("top") and cleaned[3:].isdigit():
                count = int(cleaned[3:])
                if not 1 <= count <= 10000:
                    raise ValueError("topN must be between 1 and 10000")
                out=[]; skip=False
                for a in args:
                    if skip: skip=False; continue
                    if a in ("--top-ports", "-p", "-p-"):
                        skip = True; continue
                    out.append(a)
                args = out + ["--top-ports", str(count)]
            elif len(cleaned) > 120 or any(ch not in "0123456789,-UT: " for ch in cleaned):
                raise ValueError("صيغة المنافذ غير صالحة. استخدم أمثلة مثل 22,80,443 أو T:1-65535,U:53,161")
            else:
                # Remove profile port selectors before adding the custom one.
                out=[]; skip=False
                for a in args:
                    if skip: skip=False; continue
                    if a in ("--top-ports", "-p", "-p-"):
                        skip = True
                        continue
                    out.append(a)
                # Now that raw sockets work, -sU really runs. A plain range such as
                # "1-65535" would then also be applied to UDP (65535 UDP ports takes
                # many hours because of ICMP rate limiting and can hit the scan
                # timeout). Keep each profile's own UDP scope (U:1-200) unless the
                # user picked the "maximum" audit or gave an explicit T:/U: spec.
                if "-sU" in out and scan_type != "maximum" and ":" not in cleaned:
                    cleaned = f"T:{cleaned},U:1-200"
                args = out + ["-p", cleaned]
        if timing is not None:
            if timing not in range(0,6):
                raise ValueError("timing يجب أن يكون بين 0 و5")
            args = [a for a in args if not (a.startswith("-T") and len(a)==3 and a[2].isdigit())]
            args.append(f"-T{timing}")
        return [self.nmap_binary, *args, "-oX", "-", target]

    @staticmethod
    def _harden_for_docker_host(command: list[str]) -> list[str]:
        """Exclude MIRSAD's own ports and drop NSE for loopback/Docker-host scans."""
        out: list[str] = []
        skip = False
        for i, a in enumerate(command):
            if skip:
                skip = False
                continue
            if settings.NMAP_DISABLE_NSE_ON_LOCAL:
                if a == "-sC":
                    continue
                if a == "--script":
                    skip = True
                    continue
                if a.startswith("--script="):
                    continue
            out.append(a)
        excl = (settings.NMAP_EXCLUDE_PORTS or "").strip()
        if excl and all(ch in "0123456789,-" for ch in excl):
            # insert before the "-oX - target" tail
            idx = len(out) - 3 if len(out) >= 3 and out[-3] == "-oX" else len(out) - 1
            out[idx:idx] = ["--exclude-ports", excl]
        return out

    @staticmethod
    def _unprivileged_command(command: list[str]) -> list[str]:
        out: list[str] = []
        for a in command:
            if a == "-sS": out.append("-sT"); continue
            if a in {"-sU", "-O", "--osscan-guess", "--osscan-limit"}: continue
            out.append(a)
        return out

    async def _run_nmap(self, command: list[str]) -> str:
        import time as _time
        from app.core import execution_trace as _trace
        _t0 = _time.monotonic()
        _trace.emit_command(command, timeout=settings.DEFAULT_SCAN_TIMEOUT_SECONDS)
        try:
            process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError as exc:
            raise NmapExecutionError(f"لم يتم إيجاد nmap binary: {self.nmap_binary}") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=settings.DEFAULT_SCAN_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            # Job cancelled: stop nmap instead of leaving it scanning in the background.
            if process.returncode is None:
                try: process.kill()
                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
                try: await asyncio.wait_for(asyncio.shield(process.wait()), timeout=5)
                except BaseException: logger.debug("suppressed non-fatal error", exc_info=True)
            _trace.emit_exit(command[0], None, _time.monotonic()-_t0, "CANCELLED", "CANCELLED")
            raise
        except asyncio.TimeoutError as exc:
            process.kill(); await process.wait()
            _trace.emit_exit(command[0], -124, _time.monotonic()-_t0, "TIMEOUT", "TIMEOUT")
            raise NmapExecutionError(f"انتهت مهلة الفحص ({settings.DEFAULT_SCAN_TIMEOUT_SECONDS} ثانية).") from exc
        stderr_text = stderr.decode(errors="ignore").strip()
        try:
            _xml = stdout.decode(errors="ignore")
            for _ln in _xml.splitlines():
                _l = _ln.strip()
                if _l.startswith(("<address", "<hostname", "<port ", "<state ", "<service", "<finished", "<hosts ", "<extraports", "<osmatch", "<script ")):
                    _trace.emit_output("stdout", _l)
            for _ln in stderr_text.splitlines()[:100]: _trace.emit_output("stderr", _ln)
            _trace.emit_exit(command[0], process.returncode, _time.monotonic()-_t0, "COMPLETED" if process.returncode == 0 else "FAILED")
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        if process.returncode != 0:
            raise NmapExecutionError(f"nmap فشل بكود خروج {process.returncode}: {stderr_text}")
        return stdout.decode(errors="ignore")

    @staticmethod
    def _script(elem: ET.Element) -> ScriptResult:
        return ScriptResult(script_id=elem.get("id", "unknown"), output=elem.get("output", "").strip())

    def _parse_xml(self, xml_output: str) -> dict[str, Any]:
        root = ET.fromstring(xml_output)
        hosts = root.findall("host")
        if not hosts:
            return {
                "host_up": False, "host_count": 0, "addresses": [], "hostnames": [],
                "open_ports": [], "filtered_ports_count": 0, "closed_ports_count": 0,
                "os_matches": [], "host_scripts": [], "traceroute": [],
                "scan_warnings": ["لم يُعثر على host element في XML."],
                "coverage": {"host_discovered": False, "hosts": 0, "addresses": 0, "hostnames": 0,
                             "open_ports": 0, "filtered_ports": 0, "closed_ports": 0,
                             "os_detection": False, "host_scripts": 0, "port_scripts": 0,
                             "traceroute_hops": 0},
            }
        addresses=[]; hostnames=[]; open_ports=[]; filtered=closed=0; os_matches=[]; host_scripts=[]; traceroute=[]; warnings=[]
        for host in hosts:
            status = host.find("status")
            host_up = status is not None and status.get("state") == "up"
            addresses.extend(x.get("addr") for x in host.findall("address") if x.get("addr"))
            hostnames.extend(x.get("name") for x in host.findall("hostnames/hostname") if x.get("name"))
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for p in ports_elem.findall("port"):
                    state=p.find("state"); st=state.get("state") if state is not None else "closed"
                    if st=="filtered": filtered += 1
                    elif st=="closed": closed += 1
                    service=p.find("service")
                    scripts=[self._script(x) for x in p.findall("script")]
                    cpes=[c.text for c in p.findall("service/cpe") if c.text]
                    if st in {"open","open|filtered"}: ps=PortState.OPEN
                    elif st=="filtered": ps=PortState.FILTERED
                    else: ps=PortState.CLOSED
                    open_ports.append(PortInfo(port=int(p.get("portid","0")), protocol=p.get("protocol","tcp"), state=ps,
                        service_name=service.get("name") if service is not None else None,
                        product=service.get("product") if service is not None else None,
                        version=service.get("version") if service is not None else None,
                        extra_info=service.get("extrainfo") if service is not None else None,
                        cpe=cpes, scripts=scripts))
            for m in host.findall("os/osmatch"):
                try: acc=int(m.get("accuracy","0"))
                except ValueError: acc=0
                os_matches.append(OSMatch(name=m.get("name","unknown"), accuracy=acc))
            host_scripts.extend(self._script(x) for x in host.findall("hostscript/script"))
            traceroute.extend({"ttl": h.get("ttl"), "ip": h.get("ipaddr"), "rtt": h.get("rtt"), "host": h.get("host")} for h in host.findall("trace/hop"))
            if not host_up:
                warnings.append(f"Host {addresses[-1] if addresses else 'unknown'} لم يُثبت أنه up؛ بعض النتائج قد تكون ناقصة.")
        addresses=list(dict.fromkeys(addresses)); hostnames=list(dict.fromkeys(hostnames))
        coverage={"host_discovered":any((h.find("status") is not None and h.find("status").get("state")=="up") for h in hosts),
                  "hosts":len(hosts),"addresses":len(addresses),"hostnames":len(hostnames),
                  "open_ports":sum(1 for p in open_ports if p.state==PortState.OPEN),
                  "filtered_ports":filtered,"closed_ports":closed,"os_detection":bool(os_matches),
                  "host_scripts":len(host_scripts),"port_scripts":sum(len(p.scripts) for p in open_ports),
                  "traceroute_hops":len(traceroute)}
        return {"host_up":coverage["host_discovered"],"host_count":len(hosts),"addresses":addresses,"hostnames":hostnames,
                "open_ports":open_ports,"filtered_ports_count":filtered,"closed_ports_count":closed,"os_matches":os_matches,
                "host_scripts":host_scripts,"traceroute":traceroute,"scan_warnings":warnings,"coverage":coverage}

