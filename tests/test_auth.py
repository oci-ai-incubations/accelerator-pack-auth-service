"""Tests for auth endpoints: register, login, me, users, role management."""

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
        json={"email": "admin@test.com", "password": "pass123", "name": "Admin"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["user"]["role"] == "admin"
    assert data["user"]["email"] == "admin@test.com"
    assert "access_token" in data


@pytest.mark.asyncio
async def test_register_second_user_is_pending(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "first@test.com", "password": "pass123", "name": "First"},
    )
    resp = await client.post(
        "/auth/register",
        json={"email": "second@test.com", "password": "pass123", "name": "Second"},
    )
    assert resp.status_code == 201
    assert resp.json()["user"]["role"] == "pending"


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "dup@test.com", "password": "pass123", "name": "Dup"},
    )
    resp = await client.post(
        "/auth/register",
        json={"email": "dup@test.com", "password": "pass456", "name": "Dup2"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "login@test.com", "password": "pass123", "name": "Login"},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "login@test.com", "password": "pass123"},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "wrong@test.com", "password": "pass123", "name": "Wrong"},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "wrong@test.com", "password": "badpass"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_me(client: AsyncClient):
    reg = await client.post(
        "/auth/register",
        json={"email": "me@test.com", "password": "pass123", "name": "Me"},
    )
    token = reg.json()["access_token"]
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "me@test.com"


@pytest.mark.asyncio
async def test_list_users_admin_only(client: AsyncClient):
    # Register admin (first user)
    admin = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "pass123", "name": "Admin"},
    )
    admin_token = admin.json()["access_token"]

    # Register non-admin
    user = await client.post(
        "/auth/register",
        json={"email": "user@test.com", "password": "pass123", "name": "User"},
    )
    user_token = user.json()["access_token"]

    # Admin can list
    resp = await client.get("/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    # Non-admin cannot
    resp = await client.get("/auth/users", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_user_role(client: AsyncClient):
    admin = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "pass123", "name": "Admin"},
    )
    admin_token = admin.json()["access_token"]

    user = await client.post(
        "/auth/register",
        json={"email": "promote@test.com", "password": "pass123", "name": "Promote"},
    )
    user_id = user.json()["user"]["id"]

    resp = await client.patch(
        f"/auth/users/{user_id}",
        json={"role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "user"
