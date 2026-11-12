import asyncio

from app.integrations.defectdojo.retry import _get_or_import_test


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        for index, (expected_method, expected_path, response) in enumerate(self.responses):
            if (method, path) == (expected_method, expected_path):
                self.responses.pop(index)
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"Unexpected request: {method} {path} {kwargs}")


def _run(client):
    return asyncio.run(_get_or_import_test(
        client,
        product={"id": 3, "name": "MIRSAD / tenant"},
        engagement={"id": 9, "name": "MIRSAD Scan scan-1"},
        scan_id="scan-1",
        report=b"{}",
    ))


def test_processed_test_is_reused_without_second_reimport():
    client = FakeClient([
        ("GET", "/api/v2/tests/", {"results": [
            {"id": 123, "title": "MIRSAD Scan scan-1", "engagement": 9, "status": "Processed"}
        ]}),
    ])

    assert _run(client) == 123
    assert [call[:2] for call in client.calls] == [("GET", "/api/v2/tests/")]
    assert client.calls[0][2]["params"] == {
        "engagement": 9, "title__contains": "MIRSAD Scan scan-1"
    }


def test_existing_processing_test_is_polled_instead_of_reimported(monkeypatch):
    client = FakeClient([
        ("GET", "/api/v2/tests/", {"results": [
            {"id": 123, "title": "MIRSAD Scan scan-1", "engagement": 9, "status": "Processing"}
        ]}),
        ("GET", "/api/v2/tests/123/", {"id": 123, "status": "Processing", "processing": True}),
        ("GET", "/api/v2/tests/123/", {"id": 123, "status": "Processed", "processing": False}),
    ])
    real_sleep = asyncio.sleep
    monkeypatch.setattr("app.integrations.defectdojo.retry.asyncio.sleep", lambda _seconds: real_sleep(0))
    assert _run(client) == 123
    assert not any(call[0] == "POST" for call in client.calls)


def test_missing_test_is_imported_then_waited_until_processed(monkeypatch):
    client = FakeClient([
        ("GET", "/api/v2/tests/", {"results": []}),
        ("POST", "/api/v2/reimport-scan/", {"test_id": 456}),
        ("GET", "/api/v2/tests/456/", {"id": 456, "status": "Processed", "processing": False}),
    ])
    assert _run(client) == 456
    assert any(call[0] == "POST" and call[1] == "/api/v2/reimport-scan/" for call in client.calls)


def test_failed_existing_test_is_reimported_and_processed(monkeypatch):
    client = FakeClient([
        ("GET", "/api/v2/tests/", {"results": [
            {"id": 123, "title": "MIRSAD Scan scan-1", "engagement": 9, "status": "Failed"}
        ]}),
        ("POST", "/api/v2/reimport-scan/", {"test_id": 123}),
        ("GET", "/api/v2/tests/123/", {"id": 123, "status": "Processed", "processing": False}),
    ])
    assert _run(client) == 123
    assert sum(call[0] == "POST" for call in client.calls) == 1


def test_failed_background_import_is_reported_as_retryable():
    from app.integrations.defectdojo.client import DefectDojoError

    client = FakeClient([
        ("GET", "/api/v2/tests/", {"results": []}),
        ("POST", "/api/v2/reimport-scan/", {"test_id": 789}),
        ("GET", "/api/v2/tests/789/", {"id": 789, "status": "Failed", "processing": False}),
    ])
    try:
        _run(client)
    except DefectDojoError as exc:
        assert exc.code == "IMPORT_FAILED"
        assert exc.retryable is True
    else:
        raise AssertionError("failed DefectDojo import must not be marked completed")


def test_missing_post_test_id_is_recovered_by_stable_test_lookup():
    client = FakeClient([
        ("GET", "/api/v2/tests/", {"results": []}),
        ("POST", "/api/v2/reimport-scan/", {}),
        ("GET", "/api/v2/tests/", {"results": [
            {"id": 321, "title": "MIRSAD Scan scan-1", "engagement": 9, "status": "Processed"}
        ]}),
        ("GET", "/api/v2/tests/321/", {"id": 321, "status": "Processed", "processing": False}),
    ])
    assert _run(client) == 321
