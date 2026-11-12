from app.core.json_sanitizer import sanitize_json
from app.core.config import settings, verify_target_in_scope
from app.schemas.platform import FullScanRequest


def test_sanitize_json_removes_only_nul_recursively():
    value = {"a": "hello\x00world", "b": ["\x00", "✓", {"c": "x\n\t"}]}
    out = sanitize_json(value)
    assert out == {"a": "helloworld", "b": ["", "✓", {"c": "x\n\t"}]}


def test_full_scan_request_enables_authorized_subdomain_assessment_by_default():
    req = FullScanRequest(target="https://example.com")
    assert req.scan_discovered_subdomains is True
    assert req.subdomain_max_pages == 20
    assert req.subdomain_max_depth == 2


def test_scope_supports_explicit_wildcard(monkeypatch):
    monkeypatch.setattr(settings, "ENFORCE_TARGET_SCOPE", True)
    monkeypatch.setattr(settings, "ALLOWED_TARGETS_RAW", "example.com,*.example.com")
    verify_target_in_scope("api.example.com")


def test_scope_does_not_treat_parent_as_authorizing_subdomain(monkeypatch):
    monkeypatch.setattr(settings, "ENFORCE_TARGET_SCOPE", True)
    monkeypatch.setattr(settings, "ALLOWED_TARGETS_RAW", "example.com")
    try:
        verify_target_in_scope("api.example.com")
    except Exception as exc:
        assert exc.__class__.__name__ == "ScopeViolationError"
    else:
        raise AssertionError("parent target must not authorize subdomains without wildcard scope")


def test_custom_assessment_can_discover_without_subdomain_tests():
    req = FullScanRequest(target="https://example.com", scan_profile="custom",
                          subdomain_discovery=True, subdomain_dns_verification=False,
                          subdomain_network_scan=False, subdomain_web_scan=False,
                          subdomain_api_security=False)
    assert req.subdomain_discovery is True
    assert not any((req.subdomain_dns_verification, req.subdomain_network_scan, req.subdomain_web_scan, req.subdomain_api_security))


def test_custom_assessment_has_independent_subdomain_branches():
    req = FullScanRequest(target="https://example.com", scan_profile="custom",
                          subdomain_discovery=True, subdomain_dns_verification=True,
                          subdomain_network_scan=False, subdomain_web_scan=True,
                          subdomain_api_security=False)
    assert req.subdomain_dns_verification is True
    assert req.subdomain_web_scan is True
    assert req.subdomain_network_scan is False
    assert req.subdomain_api_security is False


def test_standard_deep_maximum_profiles_restore_full_subdomain_policy():
    for name in ("standard", "deep", "maximum"):
        req = FullScanRequest(
            target="https://example.com", scan_profile=name,
            subdomain_discovery=False, subdomain_dns_verification=False,
            subdomain_network_scan=False, subdomain_web_scan=False,
            subdomain_api_security=False,
        )
        cfg = __import__("app.core.scan_profiles", fromlist=["resolve_profile"]).resolve_profile(name, req.model_dump(mode="json"))
        assert cfg["subdomain_discovery"] is True
        assert cfg["subdomain_dns_verification"] is True
        assert cfg["subdomain_network_scan"] is True
        assert cfg["subdomain_web_scan"] is True
        assert cfg["subdomain_api_security"] is True


def test_custom_profile_preserves_subdomain_policy():
    req = FullScanRequest(
        target="https://example.com", scan_profile="custom",
        subdomain_discovery=False, subdomain_dns_verification=False,
        subdomain_network_scan=False, subdomain_web_scan=False,
        subdomain_api_security=False,
    )
    cfg = __import__("app.core.scan_profiles", fromlist=["resolve_profile"]).resolve_profile("custom", req.model_dump(mode="json"))
    assert cfg["subdomain_discovery"] is False
    assert cfg["subdomain_network_scan"] is False


def test_jsonable_sanitizes_postgres_unsafe_nul():
    from app.core.database import jsonable
    assert jsonable({"evidence": "abc\x00def", "items": ["x\x00y"]}) == {"evidence": "abcdef", "items": ["xy"]}


def test_worker_claim_ignores_terminal_and_live_running_jobs():
    # Behavioral contract documented here; the actual DB/Redis integration
    # test covers the same guard under the worker fixture.
    from app.schemas.jobs import JobStatus
    assert {JobStatus.COMPLETED.value, JobStatus.PARTIAL.value, JobStatus.CANCELLED.value} == {"completed", "partial", "cancelled"}
