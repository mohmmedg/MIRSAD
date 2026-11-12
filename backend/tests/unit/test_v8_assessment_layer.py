import pytest

from app.core.scan_profiles import resolve_profile
from app.schemas.platform import FullScanRequest

def test_profiles_are_bounded_and_reproducible():
    req=FullScanRequest(target='https://example.com',scan_profile='maximum')
    cfg=resolve_profile(req.scan_profile,req.model_dump(mode='json'))
    assert cfg['scan_profile']=='maximum'
    assert cfg['max_requests']<=50000
    assert cfg['requests_per_second']<=20
    assert cfg['max_concurrency']<=16
    assert cfg['safe_mode']=='safe'

def test_custom_profile_preserves_operator_limits():
    req=FullScanRequest(target='https://example.com',scan_profile='custom',max_requests=1200,requests_per_second=2,max_concurrency=2,safe_mode='caution')
    cfg=resolve_profile('custom',req.model_dump(mode='json'))
    assert cfg['max_requests']==1200
    assert cfg['requests_per_second']==2
    assert cfg['safe_mode']=='caution'


def test_passive_profile_disables_active_engines():
    req=FullScanRequest(target='https://example.com', scan_profile='passive')
    cfg=resolve_profile('passive', req.model_dump(mode='json'))
    assert cfg['network'] is False
    assert cfg['web'] is False
    assert cfg['api'] is False
    assert cfg['subdomain_discovery'] is True
    assert cfg['subdomain_network_scan'] is False



def test_non_safe_mode_is_not_overwritten_by_standard_profile():
    for mode in ("safe", "caution", "destructive"):
        # destructive mode is only accepted with an explicit confirmation (enforced server-side)
        req = FullScanRequest(target="https://example.com", scan_profile="standard", safe_mode=mode,
                              destructive_confirmation=(mode == "destructive"))
        cfg = resolve_profile(req.scan_profile, req.model_dump(mode="json"))
        assert cfg["safe_mode"] == mode


def test_destructive_mode_without_confirmation_is_rejected():
    import pytest
    req = FullScanRequest(target="https://example.com", scan_profile="standard", safe_mode="destructive")
    with pytest.raises(ValueError, match="destructive_confirmation"):
        resolve_profile(req.scan_profile, req.model_dump(mode="json"))


def test_safety_policy_is_backend_authoritative():
    safe = FullScanRequest(target="https://example.com", scan_profile="custom", safe_mode="safe", probe_write_methods=True)
    cfg = resolve_profile("custom", safe.model_dump(mode="json"))
    assert cfg["probe_write_methods"] is False
    caution = FullScanRequest(target="https://example.com", scan_profile="custom", safe_mode="caution", probe_write_methods=False)
    cfg = resolve_profile("custom", caution.model_dump(mode="json"))
    assert cfg["probe_write_methods"] is True


def test_destructive_policy_requires_explicit_confirmation_and_enables_write_probing():
    req = FullScanRequest(target="https://example.com", scan_profile="maximum", safe_mode="destructive", destructive_confirmation=True)
    cfg = resolve_profile(req.scan_profile, req.model_dump(mode="json"))
    assert cfg["safe_mode"] == "destructive"
    assert cfg["probe_write_methods"] is True


def test_destructive_policy_without_confirmation_is_rejected():
    req = FullScanRequest(target="https://example.com", scan_profile="maximum", safe_mode="destructive")
    with pytest.raises(ValueError, match="destructive_confirmation"):
        resolve_profile(req.scan_profile, req.model_dump(mode="json"))
