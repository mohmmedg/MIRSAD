from types import SimpleNamespace
from app.core.execution_trace import add_events_to_meta, empty_stats, tally_event


def test_stats_accumulate_and_persist_via_meta():
    ex = SimpleNamespace(meta={"stats": empty_stats()})
    add_events_to_meta(ex, [
        ("http", "web_crawl", {"response": {"status": 200}}, 1),
        ("http", "web_crawl", {"response": {"status": 404}}, 2),
        ("http", "web_crawl", {"error": "boom"}, 3),
        ("command", "port_scan", {}, 4),
        ("command_exit", "port_scan", {"exit_code": 1, "state": "FAILED"}, 5),
    ])
    s = ex.meta["stats"]
    assert s["total"] == 5 and s["last_sequence"] == 5
    assert s["stages"]["web_crawl"]["http"] == 3
    assert s["buckets"]["web_crawl"] == {"req": 3, "ok": 1, "redir": 0, "c4": 1, "c5": 0, "fail": 1, "cmds": 0, "errs": 2}
    assert s["buckets"]["port_scan"]["cmds"] == 1 and s["buckets"]["port_scan"]["errs"] == 1


def test_legacy_execution_without_stats_is_left_for_backfill():
    ex = SimpleNamespace(meta={})
    add_events_to_meta(ex, [("http", "x", {}, 1)])
    assert "stats" not in ex.meta
    s = empty_stats(); tally_event(s, "stage", None, {"status": "failed"}, 9)
    assert s["buckets"]["_none"]["errs"] == 1 and s["last_sequence"] == 9
