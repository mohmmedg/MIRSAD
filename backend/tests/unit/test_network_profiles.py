from app.modules.network_scan.scanner import NetworkScanner, SCAN_PROFILES

def test_every_network_profile_builds_a_safe_command():
    scanner = NetworkScanner()
    assert len(SCAN_PROFILES) >= 8
    for profile in SCAN_PROFILES:
        command = scanner._build_command('127.0.0.1', profile, None, None)
        assert command[-3:] == ['-oX', '-', '127.0.0.1']
        assert command[0] == scanner.nmap_binary

def test_custom_ports_do_not_accept_arbitrary_nmap_flags():
    scanner = NetworkScanner()
    try:
        scanner._build_command('127.0.0.1', 'quick', '--script vuln', None)
    except ValueError:
        return
    raise AssertionError('arbitrary nmap flags must be rejected')
