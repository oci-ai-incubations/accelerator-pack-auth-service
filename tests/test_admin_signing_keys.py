"""Tests for the admin /auth/admin/signing-keys endpoints."""

import pytest
from httpx import AsyncClient


async def _register_admin(client: AsyncClient) -> str:
    reg = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return reg.json()["access_token"]


async def _register_user(client: AsyncClient) -> str:
    await client.post(
        "/auth/register",
        json={"email": "first@test.com", "password": "password123", "name": "First"},
    )
    reg = await client.post(
        "/auth/register",
        json={"email": "user@test.com", "password": "password123", "name": "User"},
    )
    return reg.json()["access_token"]


@pytest.mark.asyncio
async def test_list_signing_keys_admin(client: AsyncClient):
    token = await _register_admin(client)
    resp = await client.get(
        "/auth/admin/signing-keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) >= 1
    assert body[0]["kid"]
    assert body[0]["algorithm"] == "RS256"
    assert "private_pem" not in body[0]
    assert "public_pem" not in body[0]


@pytest.mark.asyncio
async def test_list_signing_keys_forbidden_for_non_admin(client: AsyncClient):
    token = await _register_user(client)
    resp = await client.get(
        "/auth/admin/signing-keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rotate_signing_key_admin(client: AsyncClient):
    token = await _register_admin(client)
    before = (
        await client.get(
            "/auth/admin/signing-keys",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    resp = await client.post(
        "/auth/admin/signing-keys/rotate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    new_kid = resp.json()["kid"]
    assert new_kid not in {k["kid"] for k in before}

    after = (
        await client.get(
            "/auth/admin/signing-keys",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    statuses_by_kid = {k["kid"]: k["status"] for k in after}
    assert statuses_by_kid[new_kid] == "active"
    for k in before:
        assert statuses_by_kid[k["kid"]] == "rotating_out"


@pytest.mark.asyncio
async def test_rotate_signing_key_forbidden_for_non_admin(client: AsyncClient):
    token = await _register_user(client)
    resp = await client.post(
        "/auth/admin/signing-keys/rotate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_signing_key_admin(client: AsyncClient):
    token = await _register_admin(client)
    rotate_resp = await client.post(
        "/auth/admin/signing-keys/rotate",
        headers={"Authorization": f"Bearer {token}"},
    )
    target_kid = rotate_resp.json()["kid"]
    resp = await client.delete(
        f"/auth/admin/signing-keys/{target_kid}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204

    after = (
        await client.get(
            "/auth/admin/signing-keys",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    statuses_by_kid = {k["kid"]: k["status"] for k in after}
    assert statuses_by_kid[target_kid] == "revoked"


@pytest.mark.asyncio
async def test_delete_signing_key_unknown_kid_404(client: AsyncClient):
    token = await _register_admin(client)
    resp = await client.delete(
        "/auth/admin/signing-keys/no-such-kid",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_signing_key_forbidden_for_non_admin(client: AsyncClient):
    token = await _register_user(client)
    resp = await client.delete(
        "/auth/admin/signing-keys/anything",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoked_key_invalidates_tokens(client: AsyncClient):
    """After revocation, tokens signed by the revoked kid stop validating."""
    admin_token = await _register_admin(client)
    me_before = await client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert me_before.status_code == 200

    listing = (
        await client.get(
            "/auth/admin/signing-keys",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    ).json()
    active_kid = next(k["kid"] for k in listing if k["status"] == "active")

    await client.post(
        "/auth/admin/signing-keys/rotate",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    new_login = await client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "password123"},
    )
    fresh_token = new_login.json()["access_token"]

    revoke = await client.delete(
        f"/auth/admin/signing-keys/{active_kid}",
        headers={"Authorization": f"Bearer {fresh_token}"},
    )
    assert revoke.status_code == 204

    stale = await client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert stale.status_code == 401
