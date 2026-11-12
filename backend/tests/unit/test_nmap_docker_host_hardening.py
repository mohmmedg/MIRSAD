from app.modules.network_scan.scanner import NetworkScanner


def test_docker_host_scan_excludes_own_ports_and_drops_nse():
    n = NetworkScanner()
    for profile in ("balanced", "maximum", "vulnerability"):
        cmd = n._harden_for_docker_host(n._build_command("host.docker.internal", profile, None, None))
        assert "--exclude-ports" in cmd and "8082" in cmd[cmd.index("--exclude-ports") + 1]
        assert "-sC" not in cmd and "--script" not in cmd
        assert cmd[-3:] == ["-oX", "-", "host.docker.internal"]
