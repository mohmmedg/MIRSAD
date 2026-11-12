"""
tests/unit/test_config_scope_guard.py

اختبارات لـ Scope Authorization Guard (verify_target_in_scope) وطبقة حماية
SSRF المستقلة (check_ssrf_risk) بملف app/core/config.py.
"""

import pytest

from app.core.config import ScopeViolationError, SSRFRiskError, verify_target_in_scope


class TestScopeGuard:
    def test_allowed_exact_ip(self):
        verify_target_in_scope("127.0.0.1")  # لا يرفع استثناء

    def test_allowed_hostname_exact_match(self):
        verify_target_in_scope("scanme.nmap.org")

    def test_allowed_ip_in_cidr_range(self):
        verify_target_in_scope("192.168.56.50")

    def test_rejects_out_of_scope_ip(self):
        with pytest.raises(ScopeViolationError):
            verify_target_in_scope("8.8.8.8")

    def test_rejects_out_of_scope_hostname(self):
        with pytest.raises(ScopeViolationError):
            verify_target_in_scope("google.com")

    def test_rejects_ip_just_outside_cidr(self):
        with pytest.raises(ScopeViolationError):
            verify_target_in_scope("192.168.57.1")  # خارج 192.168.56.0/24


class TestSSRFProtection:
    def test_blocks_cloud_metadata_ip(self):
        with pytest.raises(SSRFRiskError):
            verify_target_in_scope("169.254.169.254")

    def test_blocks_metadata_even_if_added_to_allowed_targets(self, monkeypatch):
        """النقطة الجوهرية بالمتطلب: SSRF check يمنع حتى لو موجود غلط
        بـ ALLOWED_TARGETS."""

        monkeypatch.setenv("ALLOWED_TARGETS", "169.254.169.254,127.0.0.1")
        # نعيد بناء settings يدوياً لمحاكاة إعادة تحميل الإعدادات بهذا الاختبار
        from app.core import config as config_module

        original_targets_raw = config_module.settings.ALLOWED_TARGETS_RAW
        config_module.settings.ALLOWED_TARGETS_RAW = "169.254.169.254,127.0.0.1"
        try:
            with pytest.raises(SSRFRiskError):
                verify_target_in_scope("169.254.169.254")
        finally:
            config_module.settings.ALLOWED_TARGETS_RAW = original_targets_raw

    def test_blocks_zero_ip(self):
        with pytest.raises(SSRFRiskError):
            verify_target_in_scope("0.0.0.0")

    def test_blocks_multicast_range(self):
        with pytest.raises(SSRFRiskError):
            verify_target_in_scope("224.0.0.5")

    def test_allows_normal_private_lab_ip(self):
        """127.0.0.1 و192.168.56.0/24 هي أهداف lab شرعية، ما لازم SSRF check يحظرها."""
        verify_target_in_scope("127.0.0.1")
        verify_target_in_scope("192.168.56.10")

    def test_ssrf_override_flag_bypasses_check(self, monkeypatch):
        from app.core import config as config_module

        config_module.settings.ALLOW_SSRF_RISK_TARGETS = True
        config_module.settings.ALLOWED_TARGETS_RAW = "169.254.169.254"
        try:
            verify_target_in_scope("169.254.169.254")  # لا يرفع استثناء بعد التفعيل
        finally:
            config_module.settings.ALLOW_SSRF_RISK_TARGETS = False
            config_module.settings.ALLOWED_TARGETS_RAW = (
                "127.0.0.1,192.168.56.0/24,scanme.nmap.org,example.com"
            )

    def test_hostname_resolution_not_blocking_for_unresolvable_host(self):
        """hostname ما ينحل (غير موجود بالـ DNS) — الفحص لازم يتجاوز بهدوء
        (الفشل الفعلي يصير لاحقاً بالـ scanner نفسه، مو هون)."""
        # هذا hostname خارج ALLOWED_TARGETS أصلاً فبيوصل لـ ScopeViolationError
        # بعد ما SSRF check يتجاوزه بهدوء (DNS فشل)
        with pytest.raises(ScopeViolationError):
            verify_target_in_scope("this-domain-should-not-resolve-xyz123.invalid")
