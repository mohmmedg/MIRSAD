import pytest

from app.api.routes.admin import _can_manage, _validate_role, _target_tenant


def test_admin_can_manage_non_privileged_users_only():
    assert _can_manage("admin", "viewer", "analyst")
    assert _can_manage("admin", "analyst", "viewer")
    assert not _can_manage("admin", "admin", "viewer")
    assert not _can_manage("admin", "owner", "admin")
    assert not _can_manage("admin", "viewer", "owner")


def test_owner_cannot_transfer_ownership():
    assert _can_manage("owner", "admin", "viewer")
    assert not _can_manage("owner", "owner", "admin")
    assert not _can_manage("owner", "viewer", "owner")


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin", "owner"])
def test_valid_roles(role):
    assert _validate_role(role) == role


def test_invalid_role():
    with pytest.raises(Exception):
        _validate_role("superuser")


async def test_owner_target_tenant_requires_a_valid_selected_organization(monkeypatch):
    class DummyDB:
        async def get(self, model, tenant_id):
            return object() if tenant_id == "tenant-b" else None

    class Scope:
        async def __aenter__(self):
            return DummyDB()
        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr("app.api.routes.admin.session_scope", lambda *_args, **_kwargs: Scope())

    class Owner:
        role = "owner"
        tenant_id = "tenant-a"

    assert await _target_tenant(Owner(), "tenant-b", required_for_owner=True) == "tenant-b"

    with pytest.raises(Exception):
        await _target_tenant(Owner(), None, required_for_owner=True)

    with pytest.raises(Exception):
        await _target_tenant(Owner(), "missing", required_for_owner=True)


async def test_admin_cannot_switch_organization():
    class Admin:
        role = "admin"
        tenant_id = "tenant-a"

    assert await _target_tenant(Admin(), None, required_for_owner=True) == "tenant-a"
    with pytest.raises(Exception):
        await _target_tenant(Admin(), "tenant-b", required_for_owner=True)
