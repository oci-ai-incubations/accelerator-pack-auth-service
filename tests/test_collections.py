"""Tests for collection-level RBAC: assign, revoke, list permissions, my-access."""

import pytest
from httpx import AsyncClient


async def _setup_admin_and_user(client: AsyncClient):
    """Helper: register admin + user, return tokens and user_id."""
    admin = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    admin_token = admin.json()["access_token"]

    user = await client.post(
        "/auth/register",
        json={"email": "user@test.com", "password": "password123", "name": "User"},
    )
    user_token = user.json()["access_token"]
    user_id = user.json()["user"]["id"]

    # Promote user from pending
    await client.patch(
        f"/auth/users/{user_id}",
        json={"role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    return admin_token, user_token, user_id


@pytest.mark.asyncio
async def test_assign_collection_permission(client: AsyncClient):
    admin_token, _, user_id = await _setup_admin_and_user(client)

    resp = await client.post(
        "/auth/collections/col-123/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["collection_id"] == "col-123"
    assert resp.json()["permission_level"] == "read"


@pytest.mark.asyncio
async def test_my_access_user(client: AsyncClient):
    admin_token, user_token, user_id = await _setup_admin_and_user(client)

    # Assign two collections
    await client.post(
        "/auth/collections/col-a/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    await client.post(
        "/auth/collections/col-b/permissions",
        json={"user_id": user_id, "permission_level": "write"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    resp = await client.get(
        "/auth/collections/my-access",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200
    access = resp.json()
    assert len(access) == 2
    ids = {a["collection_id"] for a in access}
    assert ids == {"col-a", "col-b"}


@pytest.mark.asyncio
async def test_my_access_admin_returns_empty(client: AsyncClient):
    admin_token, _, _ = await _setup_admin_and_user(client)

    resp = await client.get(
        "/auth/collections/my-access",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []  # Empty = all access


@pytest.mark.asyncio
async def test_revoke_permission(client: AsyncClient):
    admin_token, user_token, user_id = await _setup_admin_and_user(client)

    await client.post(
        "/auth/collections/col-x/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    resp = await client.delete(
        f"/auth/collections/col-x/permissions/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204

    # Verify access removed
    resp = await client.get(
        "/auth/collections/my-access",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.json() == []


@pytest.mark.asyncio
async def test_non_admin_cannot_assign(client: AsyncClient):
    _, user_token, user_id = await _setup_admin_and_user(client)

    resp = await client.post(
        "/auth/collections/col-z/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403
