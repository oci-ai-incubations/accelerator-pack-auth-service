"""Tests for Phase 2: fine-grained RBAC — roles, permissions, grants, permission checks."""

import pytest
from httpx import AsyncClient


async def _get_admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return resp.json()["access_token"]


async def _get_user_token(client: AsyncClient, admin_token: str) -> tuple[str, int]:
    resp = await client.post(
        "/auth/register",
        json={"email": "user@test.com", "password": "password123", "name": "User"},
    )
    user_id = resp.json()["user"]["id"]
    # Promote from pending to user
    await client.patch(
        f"/auth/users/{user_id}",
        json={"role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Re-login to get updated token with new role
    resp = await client.post(
        "/auth/login",
        json={"email": "user@test.com", "password": "password123"},
    )
    return resp.json()["access_token"], user_id


# ── System Roles Seeded ──────────────────────────


@pytest.mark.asyncio
async def test_system_roles_seeded(client: AsyncClient):
    """System roles (admin, user, reader, pending) should be seeded on startup."""
    token = await _get_admin_token(client)
    resp = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    roles = resp.json()
    role_names = {r["name"] for r in roles}
    assert {"admin", "user", "reader", "pending"} <= role_names
    # All should be system roles
    for r in roles:
        if r["name"] in {"admin", "user", "reader", "pending"}:
            assert r["is_system"] is True


@pytest.mark.asyncio
async def test_admin_role_has_all_permissions(client: AsyncClient):
    """Admin system role should have all system permissions."""
    token = await _get_admin_token(client)
    resp = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    admin_role = next(r for r in resp.json() if r["name"] == "admin")
    assert len(admin_role["permissions"]) >= 15  # All SYSTEM_PERMISSIONS


@pytest.mark.asyncio
async def test_user_role_has_collection_permissions(client: AsyncClient):
    """User system role should have collections:read and collections:write."""
    token = await _get_admin_token(client)
    resp = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    user_role = next(r for r in resp.json() if r["name"] == "user")
    assert "collections:read" in user_role["permissions"]
    assert "collections:write" in user_role["permissions"]


@pytest.mark.asyncio
async def test_pending_role_has_no_permissions(client: AsyncClient):
    """Pending system role should have zero permissions."""
    token = await _get_admin_token(client)
    resp = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    pending_role = next(r for r in resp.json() if r["name"] == "pending")
    assert pending_role["permissions"] == []


# ── Permissions List ─────────────────────────────


@pytest.mark.asyncio
async def test_list_permissions(client: AsyncClient):
    """Admin can list all system permissions."""
    token = await _get_admin_token(client)
    resp = await client.get("/auth/permissions", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    perms = resp.json()
    codenames = {p["codename"] for p in perms}
    assert "users:list" in codenames
    assert "collections:read" in codenames
    assert "roles:create" in codenames


@pytest.mark.asyncio
async def test_non_admin_cannot_list_permissions(client: AsyncClient):
    """Non-admin user should be denied access to permissions list."""
    admin_token = await _get_admin_token(client)
    user_token, _ = await _get_user_token(client, admin_token)
    resp = await client.get("/auth/permissions", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403


# ── Role CRUD ────────────────────────────────────


@pytest.mark.asyncio
async def test_create_custom_role(client: AsyncClient):
    """Admin can create a custom role."""
    token = await _get_admin_token(client)
    resp = await client.post(
        "/auth/roles",
        json={"name": "analyst", "description": "Data analyst role"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "analyst"
    assert data["is_system"] is False
    assert data["permissions"] == []


@pytest.mark.asyncio
async def test_create_duplicate_role_fails(client: AsyncClient):
    """Creating a role with an existing name should fail."""
    token = await _get_admin_token(client)
    await client.post(
        "/auth/roles",
        json={"name": "dup-role"},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.post(
        "/auth/roles",
        json={"name": "dup-role"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_update_custom_role(client: AsyncClient):
    """Admin can update a custom role."""
    token = await _get_admin_token(client)
    create = await client.post(
        "/auth/roles",
        json={"name": "editable"},
        headers={"Authorization": f"Bearer {token}"},
    )
    role_id = create.json()["id"]

    resp = await client.patch(
        f"/auth/roles/{role_id}",
        json={"name": "renamed", "description": "Updated desc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed"
    assert resp.json()["description"] == "Updated desc"


@pytest.mark.asyncio
async def test_cannot_modify_system_role(client: AsyncClient):
    """System roles cannot be modified."""
    token = await _get_admin_token(client)
    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    admin_role = next(r for r in roles.json() if r["name"] == "admin")

    resp = await client.patch(
        f"/auth/roles/{admin_role['id']}",
        json={"name": "superadmin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_custom_role(client: AsyncClient):
    """Admin can delete a custom role."""
    token = await _get_admin_token(client)
    create = await client.post(
        "/auth/roles",
        json={"name": "deletable"},
        headers={"Authorization": f"Bearer {token}"},
    )
    role_id = create.json()["id"]

    resp = await client.delete(
        f"/auth/roles/{role_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_cannot_delete_system_role(client: AsyncClient):
    """System roles cannot be deleted."""
    token = await _get_admin_token(client)
    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    admin_role = next(r for r in roles.json() if r["name"] == "admin")

    resp = await client.delete(
        f"/auth/roles/{admin_role['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


# ── Role Permissions ─────────────────────────────


@pytest.mark.asyncio
async def test_set_role_permissions(client: AsyncClient):
    """Admin can set permissions on a custom role."""
    token = await _get_admin_token(client)
    create = await client.post(
        "/auth/roles",
        json={"name": "custom-perms"},
        headers={"Authorization": f"Bearer {token}"},
    )
    role_id = create.json()["id"]

    resp = await client.put(
        f"/auth/roles/{role_id}/permissions",
        json={"permission_codenames": ["collections:read", "collections:write"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert set(resp.json()["permissions"]) == {"collections:read", "collections:write"}


# ── Permission Check ─────────────────────────────


@pytest.mark.asyncio
async def test_permission_check_admin_has_all(client: AsyncClient):
    """Admin should have any permission checked."""
    token = await _get_admin_token(client)
    # Get admin user id
    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    admin_id = me.json()["id"]

    resp = await client.post(
        "/auth/permissions/check",
        json={"user_id": admin_id, "permission": "users:list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is True


@pytest.mark.asyncio
async def test_permission_check_user_has_collections_read(client: AsyncClient):
    """User role should have collections:read via legacy role mapping."""
    admin_token = await _get_admin_token(client)
    _, user_id = await _get_user_token(client, admin_token)

    resp = await client.post(
        "/auth/permissions/check",
        json={"user_id": user_id, "permission": "collections:read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is True


@pytest.mark.asyncio
async def test_permission_check_user_lacks_admin_perms(client: AsyncClient):
    """User role should NOT have admin permissions."""
    admin_token = await _get_admin_token(client)
    _, user_id = await _get_user_token(client, admin_token)

    resp = await client.post(
        "/auth/permissions/check",
        json={"user_id": user_id, "permission": "users:list"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is False


# ── User Role Assignments ────────────────────────


@pytest.mark.asyncio
async def test_assign_and_list_user_roles(client: AsyncClient):
    """Admin can assign a role to a user and list it."""
    admin_token = await _get_admin_token(client)
    _, user_id = await _get_user_token(client, admin_token)

    # Get a role to assign
    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {admin_token}"})
    reader_role = next(r for r in roles.json() if r["name"] == "reader")

    # Assign
    resp = await client.post(
        f"/auth/users/{user_id}/roles",
        json={"role_id": reader_role["id"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["role_name"] == "reader"

    # List
    resp = await client.get(
        f"/auth/users/{user_id}/roles",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_remove_user_role(client: AsyncClient):
    """Admin can remove a role assignment from a user."""
    admin_token = await _get_admin_token(client)
    _, user_id = await _get_user_token(client, admin_token)

    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {admin_token}"})
    reader_role = next(r for r in roles.json() if r["name"] == "reader")

    assign = await client.post(
        f"/auth/users/{user_id}/roles",
        json={"role_id": reader_role["id"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assignment_id = assign.json()["id"]

    resp = await client.delete(
        f"/auth/users/{user_id}/roles/{assignment_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


# ── Legacy Backward Compatibility ────────────────


@pytest.mark.asyncio
async def test_legacy_collection_endpoints_still_work(client: AsyncClient):
    """Legacy collection permission endpoints should still work after Phase 2."""
    admin_token = await _get_admin_token(client)
    user_token, user_id = await _get_user_token(client, admin_token)

    # Assign
    resp = await client.post(
        "/auth/collections/col-legacy/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201

    # My access
    resp = await client.get(
        "/auth/collections/my-access",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_require_permission_blocks_unauthorized(client: AsyncClient):
    """require_permission dependency should block users without the permission."""
    admin_token = await _get_admin_token(client)
    user_token, _ = await _get_user_token(client, admin_token)

    # User (non-admin) should be blocked from roles:list
    resp = await client.get("/auth/roles", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403
    assert "roles:list" in resp.json()["detail"]
