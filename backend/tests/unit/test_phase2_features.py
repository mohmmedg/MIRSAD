from app.modules.ci_policy import CIPolicy
from app.modules.auth_session.engine import AuthProfile
from app.modules.reporting.exporters import to_csv, to_sarif, to_json
from app.modules.plugin_registry import PluginRegistry, Plugin
from app.schemas.platform import UnifiedScanResult
from datetime import datetime, timezone

def scan(): return UnifiedScanResult(scan_id='1',target='https://example.com',status='completed',started_at=datetime.now(timezone.utc),findings=[])

def test_ci_policy():
    assert CIPolicy().evaluate([])['passed']

def test_auth_profile():
    p=AuthProfile.from_input('test','bearer','SECRET'); assert p.headers['Authorization']=='Bearer SECRET'

def test_report_formats():
    s=scan(); assert 'scan_id' in to_json(s); assert 'finding_id' in to_csv(s); assert to_sarif(s)['version']=='2.1.0'

def test_plugin_registry():
    r=PluginRegistry(); r.register(Plugin('x','1','engine',lambda:None)); assert r.list()[0]['name']=='x'
