import asyncio
import contextlib

from app.core import canonical_artifacts as ca
from app.core.config import settings


class _FakeDB:
    def __init__(self, sink):
        self.sink = sink

    def add(self, row):
        self.sink.append(row)


def _make_recorder(monkeypatch, sink, sessions):
    @contextlib.asynccontextmanager
    async def fake_scope(tenant_id=None):
        sessions.append(1)
        yield _FakeDB(sink)

    monkeypatch.setattr(ca, "session_scope", fake_scope)
    monkeypatch.setattr(ca, "encrypt_artifact", lambda raw: raw)
    monkeypatch.setattr(ca, "RawArtifactRow", lambda **kw: type("Row", (), kw)())
    rec = object.__new__(ca.CanonicalStreamRecorder)
    rec.scan_id, rec.engine, rec.execution_id, rec.tenant_id = "s", "nuclei", None, "t"
    rec.engine_result_id, rec.part_index, rec.artifact_ids = "eng_x", 0, []
    rec._chunks = {"stdout": [], "stderr": []}
    rec._chunk_lock = asyncio.Lock()
    rec._pending = {"stdout": [], "stderr": []}
    rec._pending_bytes = 0
    rec._last_flush = __import__("time").monotonic()
    return rec


def test_many_lines_use_few_db_sessions_and_lose_nothing(monkeypatch):
    monkeypatch.setattr(settings, "SCANNER_CHUNK_FLUSH_BYTES", 2048, raising=False)
    monkeypatch.setattr(settings, "SCANNER_CHUNK_FLUSH_SECONDS", 60.0, raising=False)
    sink, sessions = [], []
    rec = _make_recorder(monkeypatch, sink, sessions)

    async def run():
        for i in range(1000):
            await rec.on_chunk("stdout", f"line {i:04d} some scanner output\n")
        await rec.flush()

    asyncio.run(run())
    assert len(sessions) < 50  # was 1000 sessions before batching
    assert b"".join(r.content for r in sink) == b"".join(rec._chunks["stdout"])
    assert len(rec.artifact_ids) == len(sink)


def test_stderr_aggregate_is_never_attached_as_stdout_evidence():
    assert ca._aggregate_stdout_id({"stderr": "art_stderr"}) is None
    assert ca._aggregate_stdout_id({"stdout": "art_stdout", "stderr": "art_stderr"}) == "art_stdout"
