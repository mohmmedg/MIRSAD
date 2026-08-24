"""
tests/conftest.py

Fixtures مشتركة لكل الاختبارات. مهم جداً: نضبط متغيرات البيئة بمستوى
الموديول (وقت تحميل conftest.py نفسه) — وليس داخل fixture — لأن
app.core.config.settings يُبنى مرة واحدة عند أول import، وpytest يستورد
conftest.py قبل أي ملف اختبار آخر، فهذا يضمن أن settings يُبنى بالقيم
الصحيحة من البداية.
"""

import os

os.environ["ENVIRONMENT"] = "development"
os.environ["API_KEY"] = "test-api-key"
os.environ["ALLOWED_TARGETS"] = "127.0.0.1,192.168.56.0/24,scanme.nmap.org,example.com"
os.environ["ENFORCE_TARGET_SCOPE"] = "true"
os.environ["GEMINI_API_KEY"] = ""
os.environ["DATA_DIR"] = "/tmp/security-scanner-test-data"
os.environ["DATABASE_URL"] = "sqlite:////tmp/security-scanner-test-data/test.db"
# Keep the suite deterministic across repeated local/CI runs. The application
# intentionally persists state, so tests must start from a clean isolated DB.
import shutil
shutil.rmtree(os.environ["DATA_DIR"], ignore_errors=True)
os.makedirs(os.environ["DATA_DIR"], exist_ok=True)
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"  # ما نريد rate limiting يتدخل بالاختبارات العامة
os.environ["CORS_ORIGINS"] = "http://localhost:3000"

import pytest


@pytest.fixture
def api_key_headers():
    return {"X-API-Key": "test-api-key"}


@pytest.fixture
def sample_network_scan_completed():
    """NetworkScanResult جاهز (completed) لاستخدامه بعدة اختبارات دون تكرار."""
    from datetime import datetime, timezone

    from app.schemas.network import (
        NetworkScanResult,
        OSMatch,
        PortInfo,
        PortState,
        ScanStatus,
    )

    return NetworkScanResult(
        scan_id="test-scan-1",
        target="127.0.0.1",
        scan_type="quick",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration_seconds=1.2,
        open_ports=[
            PortInfo(port=22, protocol="tcp", state=PortState.OPEN, service_name="ssh"),
            PortInfo(
                port=21,
                protocol="tcp",
                state=PortState.OPEN,
                service_name="ftp",
                product="vsftpd",
                version="2.3.4",
            ),
        ],
        os_matches=[OSMatch(name="Linux 5.X", accuracy=95)],
        raw_nmap_command="nmap -sV -oX - 127.0.0.1",
    )


@pytest.fixture
def sample_web_scan_completed():
    from datetime import datetime, timezone

    from app.schemas.network import ScanStatus
    from app.schemas.web import HeaderCheck, TLSInfo, WebScanResult

    return WebScanResult(
        scan_id="test-web-scan-1",
        target="https://example.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        duration_seconds=0.8,
        tls_info=TLSInfo(enabled=True, protocol_version="TLSv1.3", certificate_valid=True, days_until_expiry=60),
        security_headers=[
            HeaderCheck(header_name="Content-Security-Policy", present=False),
            HeaderCheck(header_name="Strict-Transport-Security", present=True, value="max-age=31536000"),
        ],
        vulnerability_checks=[],
        server_header="nginx",
    )
