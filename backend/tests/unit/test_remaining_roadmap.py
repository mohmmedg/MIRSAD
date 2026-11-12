from app.modules.compliance import frameworks, controls, assess
from app.modules.importers.nmap_xml import parse_nmap_xml


def test_yaml_frameworks_are_loaded_and_assessable():
    names = frameworks()
    assert names
    assert controls(names[0])
    result = assess([], framework=names[0], coverage={"capabilities": {}})
    assert result["framework"] == names[0]
    assert "controls" in result


def test_nmap_import_is_unverified_and_normalized():
    xml = b'''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="test"/></port></ports></host></nmaprun>'''
    rows = parse_nmap_xml(xml, "import-test")
    assert rows
    assert all(r.verification_status == "DETECTED" for r in rows)
    assert all(r.source_module for r in rows)
