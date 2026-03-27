"""Tests for Phase 4: SCIM 2.0 provisioning, groups, group-role sync."""

import pytest
from httpx import AsyncClient

SCIM_TOKEN = "test-scim-token"
SCIM_HEADERS = {"Authorization": f"Bearer {SCIM_TOKEN}"}


async def _get_admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return resp.json()["access_token"]


# ── SCIM Discovery ───────────────────────────────


@pytest.mark.asyncio
async def test_scim_service_provider_config(client: AsyncClient):
    resp = await client.get("/scim/v2/ServiceProviderConfig", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert "schemas" in resp.json()


@pytest.mark.asyncio
async def test_scim_schemas(client: AsyncClient):
    resp = await client.get("/scim/v2/Schemas", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_scim_resource_types(client: AsyncClient):
    resp = await client.get("/scim/v2/ResourceTypes", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_scim_invalid_token_rejected(client: AsyncClient):
    resp = await client.get(
        "/scim/v2/ServiceProviderConfig",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


# ── SCIM Users ───────────────────────────────────


@pytest.mark.asyncio
async def test_scim_create_user(client: AsyncClient):
    resp = await client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim-user@example.com",
            "displayName": "SCIM User",
            "active": True,
        },
        headers=SCIM_HEADERS,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["userName"] == "scim-user@example.com"
    assert data["active"] is True


@pytest.mark.asyncio
async def test_scim_list_users(client: AsyncClient):
    # Create a user first
    await client.post(
        "/scim/v2/Users",
        json={"userName": "list-user@example.com", "displayName": "List"},
        headers=SCIM_HEADERS,
    )
    resp = await client.get("/scim/v2/Users", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["totalResults"] >= 1


@pytest.mark.asyncio
async def test_scim_get_user(client: AsyncClient):
    create = await client.post(
        "/scim/v2/Users",
        json={"userName": "get-user@example.com", "displayName": "Get"},
        headers=SCIM_HEADERS,
    )
    uid = create.json()["id"]
    resp = await client.get(f"/scim/v2/Users/{uid}", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["userName"] == "get-user@example.com"


@pytest.mark.asyncio
async def test_scim_update_user(client: AsyncClient):
    create = await client.post(
        "/scim/v2/Users",
        json={"userName": "update-scim@example.com", "displayName": "Before"},
        headers=SCIM_HEADERS,
    )
    uid = create.json()["id"]
    resp = await client.put(
        f"/scim/v2/Users/{uid}",
        json={"displayName": "After", "active": False},
        headers=SCIM_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["displayName"] == "After"
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_scim_delete_user_deactivates(client: AsyncClient):
    """SCIM delete should deactivate, not hard delete."""
    create = await client.post(
        "/scim/v2/Users",
        json={"userName": "delete-scim@example.com", "displayName": "Delete"},
        headers=SCIM_HEADERS,
    )
    uid = create.json()["id"]
    resp = await client.delete(f"/scim/v2/Users/{uid}", headers=SCIM_HEADERS)
    assert resp.status_code == 204

    # User should still exist but be inactive
    get = await client.get(f"/scim/v2/Users/{uid}", headers=SCIM_HEADERS)
    assert get.status_code == 200
    assert get.json()["active"] is False


@pytest.mark.asyncio
async def test_scim_create_duplicate_user_fails(client: AsyncClient):
    await client.post(
        "/scim/v2/Users",
        json={"userName": "dup-scim@example.com", "displayName": "Dup"},
        headers=SCIM_HEADERS,
    )
    resp = await client.post(
        "/scim/v2/Users",
        json={"userName": "dup-scim@example.com", "displayName": "Dup2"},
        headers=SCIM_HEADERS,
    )
    assert resp.status_code == 409


# ── SCIM Groups ──────────────────────────────────


@pytest.mark.asyncio
async def test_scim_create_group(client: AsyncClient):
    resp = await client.post(
        "/scim/v2/Groups",
        json={"displayName": "Engineering", "externalId": "eng-001"},
        headers=SCIM_HEADERS,
    )
    assert resp.status_code == 201
    assert resp.json()["displayName"] == "Engineering"


@pytest.mark.asyncio
async def test_scim_list_groups(client: AsyncClient):
    await client.post(
        "/scim/v2/Groups",
        json={"displayName": "List Group"},
        headers=SCIM_HEADERS,
    )
    resp = await client.get("/scim/v2/Groups", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["totalResults"] >= 1


@pytest.mark.asyncio
async def test_scim_update_group(client: AsyncClient):
    create = await client.post(
        "/scim/v2/Groups",
        json={"displayName": "Old Group"},
        headers=SCIM_HEADERS,
    )
    gid = create.json()["id"]
    resp = await client.put(
        f"/scim/v2/Groups/{gid}",
        json={"displayName": "New Group"},
        headers=SCIM_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["displayName"] == "New Group"


@pytest.mark.asyncio
async def test_scim_delete_group(client: AsyncClient):
    create = await client.post(
        "/scim/v2/Groups",
        json={"displayName": "Delete Group"},
        headers=SCIM_HEADERS,
    )
    gid = create.json()["id"]
    resp = await client.delete(f"/scim/v2/Groups/{gid}", headers=SCIM_HEADERS)
    assert resp.status_code == 204

    get = await client.get(f"/scim/v2/Groups/{gid}", headers=SCIM_HEADERS)
    assert get.status_code == 404


# ── Admin Group Management ───────────────────────


@pytest.mark.asyncio
async def test_admin_create_and_list_groups(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.post(
        "/auth/groups",
        json={"name": "test-group", "display_name": "Test Group"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "test-group"

    resp = await client.get("/auth/groups", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert any(g["name"] == "test-group" for g in resp.json())


@pytest.mark.asyncio
async def test_group_member_management(client: AsyncClient):
    token = await _get_admin_token(client)

    # Create group
    group = await client.post(
        "/auth/groups",
        json={"name": "members-group"},
        headers={"Authorization": f"Bearer {token}"},
    )
    gid = group.json()["id"]

    # Create a user
    user = await client.post(
        "/auth/register",
        json={"email": "member@test.com", "password": "password123", "name": "Member"},
    )
    uid = user.json()["user"]["id"]

    # Add member
    resp = await client.post(
        f"/auth/groups/{gid}/members",
        json={"user_id": uid},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201

    # List members
    resp = await client.get(
        f"/auth/groups/{gid}/members",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # Remove member
    resp = await client.delete(
        f"/auth/groups/{gid}/members/{uid}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_group_role_sync(client: AsyncClient):
    token = await _get_admin_token(client)

    # Create group
    group = await client.post(
        "/auth/groups",
        json={"name": "role-group"},
        headers={"Authorization": f"Bearer {token}"},
    )
    gid = group.json()["id"]

    # Get reader role id
    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    reader_role = next(r for r in roles.json() if r["name"] == "reader")

    # Set group roles
    resp = await client.put(
        f"/auth/groups/{gid}/roles",
        json={"role_ids": [reader_role["id"]]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert reader_role["id"] in resp.json()["role_ids"]
