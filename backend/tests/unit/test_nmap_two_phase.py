import asyncio

from app.modules.network_scan.scanner import NetworkScanner


def _xml(ports):
    body = "".join(f'<port protocol="{p}" portid="{n}"><state state="open"/><service name="s"/></port>' for p, n in ports)
    return f'<nmaprun><host><status state="up"/><address addr="10.0.0.5"/><ports>{body}</ports></host></nmaprun>'


def test_two_phase_commands_split_discovery_detail_and_udp():
    sc = NetworkScanner()
    cmd = sc._build_command("10.0.0.5", "maximum", None, None)
    p1, p2, udp = sc._two_phase_commands(cmd)
    assert "-sV" not in p1 and "-sC" not in p1 and "-O" not in p1 and "--script" not in p1
    assert "--min-rate" in p1 and "-sU" not in p1 and p1[p1.index("-p") + 1] == "1-65535"
    assert "@PORTS@" in p2 and "-sV" in p2 and "-sU" not in p2 and "--script" in p2
    assert udp is not None and "-sU" in udp and "-sS" not in udp and "--script" in udp and "-O" not in udp
    # TCP discovery keeps default retransmissions (completeness); UDP is bounded since 2026-10-13:
    # a full 1-65535 UDP sweep is ICMP rate-limited and took hours.
    assert "--max-retries" not in p1
    assert "--max-retries" in udp and "--host-timeout" in udp and "1-65535" not in " ".join(udp)


def test_two_phase_merges_tcp_detail_and_udp_and_skips_detail_without_open_ports():
    sc = NetworkScanner()
    calls = []

    async def fake(cmd):
        calls.append(cmd)
        if "-sU" in cmd:
            return _xml([("udp", 53)])
        return _xml([("tcp", 22), ("tcp", 3000)])

    sc._run_nmap = fake
    cmd = sc._build_command("10.0.0.5", "deep", None, None)
    parsed, _ = asyncio.run(sc._scan_two_phase(cmd, False))
    assert {(p.protocol, p.port) for p in parsed["open_ports"]} == {("tcp", 22), ("tcp", 3000), ("udp", 53)}
    assert any("1,22,3000" in c for c in calls)

    calls.clear()

    async def none_open(cmd):
        calls.append(cmd)
        return _xml([])

    sc._run_nmap = none_open
    cmd = sc._build_command("10.0.0.5", "comprehensive", None, None)
    parsed, _ = asyncio.run(sc._scan_two_phase(cmd, False))
    assert len(calls) == 1 and parsed["open_ports"] == []
