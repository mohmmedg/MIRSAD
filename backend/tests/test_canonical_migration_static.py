from pathlib import Path

def test_canonical_migration_is_additive_and_rls_scoped():
    sql=Path(__file__).parents[2]/"supabase"/"migrations"/"0028_canonical_hardening.sql"
    text=sql.read_text(encoding="utf-8").lower()
    assert "create table if not exists public.raw_artifacts" in text
    assert "create table if not exists public.engine_results" in text
    assert "create table if not exists public.finding_sources" in text
    assert "enable row level security" in text and "force row level security" in text
    assert "tenant_id = current_setting(''app.tenant_id'', true)" in text
    assert "create trigger trg_raw_artifacts_immutable" in text
    # Direct destructive data operations are forbidden by the canonical migration contract.
    assert "drop table" not in text
    assert "truncate" not in text
    assert "delete from" not in text
