"""Tests for require_pack_permission factory."""

import pytest
from fastapi import HTTPException

from accelerator_pack_auth_service.auth import require_pack_permission
from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.models import Role, User


def _user(role: Role) -> User:
    u = User()
    u.id = 1
    u.email = "u@example.com"
    u.name = "U"
    u.role = role
    u.is_active = True
    return u


@pytest.mark.asyncio
async def test_admin_always_passes(monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    dep = require_pack_permission("admin.users.manage")
    # admin bypass — no need to consult the pack model
    result = await dep(_user(Role.admin))
    assert result.role == Role.admin


@pytest.mark.asyncio
async def test_user_with_allowed_perm_passes(monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    dep = require_pack_permission("cuopt.solve")
    result = await dep(_user(Role.user))
    assert result.role == Role.user


@pytest.mark.asyncio
async def test_user_missing_perm_403s(monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    dep = require_pack_permission("admin.users.manage")
    with pytest.raises(HTTPException) as exc:
        await dep(_user(Role.user))
    assert exc.value.status_code == 403
    assert "admin.users.manage" in exc.value.detail


@pytest.mark.asyncio
async def test_reader_can_view_but_not_solve(monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    view_dep = require_pack_permission("cuopt.view")
    solve_dep = require_pack_permission("cuopt.solve")

    reader = _user(Role.reader)
    assert (await view_dep(reader)).role == Role.reader

    with pytest.raises(HTTPException) as exc:
        await solve_dep(reader)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_unknown_pack_falls_back_to_base(monkeypatch):
    """Unknown AUTH_PACK loads BASE_MODEL — user role has no perms."""
    monkeypatch.setattr(settings, "pack", "no-such-pack")
    dep = require_pack_permission("admin.users.manage")
    with pytest.raises(HTTPException):
        await dep(_user(Role.user))
