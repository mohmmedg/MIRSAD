from app.core.scan_store import InMemoryScanStore


def test_each_scan_gets_unique_independent_record():
    store = InMemoryScanStore()
    first = store.create("network", "127.0.0.1")
    second = store.create("network", "127.0.0.1")
    assert first.scan_id != second.scan_id
    store.mark_running(first.scan_id)
    assert store.get(first.scan_id).status.value == "running"
    assert store.get(second.scan_id).status.value == "pending"
