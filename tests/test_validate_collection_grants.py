"""Tests for collection-grant propagation through /auth/validate (user path).

Downstream services (e.g. OGX/llama-stack) validate every request by POSTing
``{"api_key": <jwt>}`` to /auth/validate and authorize based on the returned
``attributes``. For per-collection access to work, the user's explicit
collection grants must be surfaced as an ``attributes.collections`` list —
otherwise OGX's resource policy never learns about them and drops granted
vector stores from /v1/vector_stores. See redbull-racing-demo#19.
"""

import pytest
from httpx import AsyncClient


async def _register_admin(client: AsyncClient) -> str:
    # The first user registered on a fresh deployment is promoted to admin.
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@grants.example.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


async def _register_user(client: AsyncClient, admin_token: str) -> tuple[str, int]:
    resp = await client.post(
        "/auth/register",
        json={"email": "foobar@oracle.com", "password": "password123", "name": "Foobar"},
    )
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user"]["id"]
    # Promote from pending to user, then re-login for a token carrying the new role.
    await client.patch(
        f"/auth/users/{user_id}",
        json={"role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "foobar@oracle.com", "password": "password123"},
    )
    return resp.json()["access_token"], user_id


@pytest.mark.asyncio
async def test_validate_surfaces_collection_grants(client: AsyncClient):
    admin_token = await _register_admin(client)
    user_token, user_id = await _register_user(client, admin_token)
    collection_id = "vs_5ceb9ddd-ed3e-4fd8-aeab-2864a8976d37"

    # Before any grant, the user's collections attribute is empty.
    resp = await client.post("/auth/validate", json={"api_key": user_token})
    assert resp.status_code == 200, resp.text
    assert resp.json()["attributes"]["collections"] == []

    # Admin grants foobar read access on the collection.
    grant = await client.post(
        f"/auth/collections/{collection_id}/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert grant.status_code == 201, grant.text

    # /auth/validate now surfaces the grant so OGX can permit read on the store.
    resp = await client.post("/auth/validate", json={"api_key": user_token})
    assert resp.status_code == 200, resp.text
    attributes = resp.json()["attributes"]
    assert attributes["collections"] == [collection_id]
    # Existing attributes are unchanged.
    assert attributes["roles"] == ["user"]
    assert attributes["email"] == ["foobar@oracle.com"]


@pytest.mark.asyncio
async def test_validate_revoked_grant_disappears(client: AsyncClient):
    admin_token = await _register_admin(client)
    user_token, user_id = await _register_user(client, admin_token)
    collection_id = "vs_5ceb9ddd-ed3e-4fd8-aeab-2864a8976d37"

    grant = await client.post(
        f"/auth/collections/{collection_id}/permissions",
        json={"user_id": user_id, "permission_level": "read"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert grant.status_code == 201, grant.text

    revoke = await client.delete(
        f"/auth/collections/{collection_id}/permissions/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke.status_code in (200, 204), revoke.text

    resp = await client.post("/auth/validate", json={"api_key": user_token})
    assert resp.status_code == 200, resp.text
    assert resp.json()["attributes"]["collections"] == []
