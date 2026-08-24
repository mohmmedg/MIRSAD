import pytest

from app.api.routes.admin import _can_manage, _validate_role


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
