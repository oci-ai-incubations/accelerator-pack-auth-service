"""Tests for auth endpoints: register, login, refresh, logout, users."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/auth/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_register_first_user_is_admin(client: AsyncClient):
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["user"]["role"] == "admin"
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_register_second_user_is_pending(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "first@test.com", "password": "password123", "name": "First"},
    )
    resp = await client.post(
        "/auth/register",
        json={"email": "second@test.com", "password": "password123", "name": "Second"},
    )
    assert resp.status_code == 201
    assert resp.json()["user"]["role"] == "pending"


@pytest.mark.asyncio
async def test_register_password_too_short(client: AsyncClient):
    resp = await client.post(
        "/auth/register",
        json={"email": "short@test.com", "password": "abc", "name": "Short"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "dup@test.com", "password": "password123", "name": "Dup"},
    )
    resp = await client.post(
        "/auth/register",
        json={"email": "dup@test.com", "password": "password456", "name": "Dup2"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "login@test.com", "password": "password123", "name": "Login"},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "login@test.com", "password": "password123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "wrong@test.com", "password": "password123", "name": "Wrong"},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "wrong@test.com", "password": "badpassword"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_flow(client: AsyncClient):
    reg = await client.post(
        "/auth/register",
        json={"email": "refresh@test.com", "password": "password123", "name": "Refresh"},
    )
    refresh_token = reg.json()["refresh_token"]

    resp = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    # Old refresh token should be revoked (rotation)
    assert data["refresh_token"] != refresh_token


@pytest.mark.asyncio
async def test_refresh_token_reuse_fails(client: AsyncClient):
    reg = await client.post(
        "/auth/register",
        json={"email": "reuse@test.com", "password": "password123", "name": "Reuse"},
    )
    refresh_token = reg.json()["refresh_token"]

    # First use succeeds
    await client.post("/auth/refresh", json={"refresh_token": refresh_token})

    # Second use fails (token was rotated)
    resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_tokens(client: AsyncClient):
    reg = await client.post(
        "/auth/register",
        json={"email": "logout@test.com", "password": "password123", "name": "Logout"},
    )
    access_token = reg.json()["access_token"]
    refresh_token = reg.json()["refresh_token"]

    resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 204

    # Refresh should fail after logout
    resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_me(client: AsyncClient):
    reg = await client.post(
        "/auth/register",
        json={"email": "me@test.com", "password": "password123", "name": "Me"},
    )
    token = reg.json()["access_token"]
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "me@test.com"


@pytest.mark.asyncio
async def test_list_users_admin_only(client: AsyncClient):
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

    resp = await client.get("/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    resp = await client.get("/auth/users", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_user_role(client: AsyncClient):
    admin = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    admin_token = admin.json()["access_token"]

    user = await client.post(
        "/auth/register",
        json={"email": "promote@test.com", "password": "password123", "name": "Promote"},
    )
    user_id = user.json()["user"]["id"]

    resp = await client.patch(
        f"/auth/users/{user_id}",
        json={"role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "user"


@pytest.mark.asyncio
async def test_security_headers(client: AsyncClient):
    resp = await client.get("/auth/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
