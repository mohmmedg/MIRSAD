"""The worker must refuse to start with a DB role that RLS hides every job from."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app.core import database


def _fake_session(dialect: str, bypass):
    class Db:
        def get_bind(self): return SimpleNamespace(dialect=SimpleNamespace(name=dialect))
        def execute(self, *_a, **_k): return SimpleNamespace(scalar=lambda: bypass)

    @contextmanager
    def scope(*_a, **_k):
        yield Db()
    return scope


def test_role_without_bypassrls_is_rejected(monkeypatch):
    monkeypatch.setattr(database, "session_scope_sync", _fake_session("postgresql", False))
    with pytest.raises(SystemExit, match="worker_role.sql"):
        database.require_rls_bypass_role()


def test_role_with_bypassrls_or_superuser_is_accepted(monkeypatch):
    monkeypatch.setattr(database, "session_scope_sync", _fake_session("postgresql", True))
    database.require_rls_bypass_role()


def test_non_postgres_dialect_is_skipped(monkeypatch):
    monkeypatch.setattr(database, "session_scope_sync", _fake_session("sqlite", False))
    database.require_rls_bypass_role()
