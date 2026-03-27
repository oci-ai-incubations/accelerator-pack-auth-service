"""Tests for Phase 1: token blacklist, account lockout, token revoke, session limit, alive."""

import pytest
from httpx import AsyncClient

# ── Liveness ──────────────────────────────────────


@pytest.mark.asyncio
async def test_alive(client: AsyncClient):
    resp = await client.get("/auth/alive")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


# ── Token Blacklist ───────────────────────────────


@pytest.mark.asyncio
async def test_logout_blacklists_access_token(client: AsyncClient):
    """After logout, the access token should be rejected."""
    reg = await client.post(
        "/auth/register",
        json={"email": "bl@test.com", "password": "password123", "name": "BL"},
    )
    access_token = reg.json()["access_token"]

    # Logout
    resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 204

    # Access token should now be blacklisted
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_revoke_specific_token(client: AsyncClient):
    """POST /auth/token/revoke should blacklist a specific access token."""
    reg = await client.post(
        "/auth/register",
        json={"email": "revoke@test.com", "password": "password123", "name": "Revoke"},
    )
    access_token = reg.json()["access_token"]

    # Login again to get a second token
    login = await client.post(
        "/auth/login",
        json={"email": "revoke@test.com", "password": "password123"},
    )
    second_token = login.json()["access_token"]

    # Revoke the first token using the second
    resp = await client.post(
        "/auth/token/revoke",
        json={"token": access_token},
        headers={"Authorization": f"Bearer {second_token}"},
    )
    assert resp.status_code == 204

    # First token should be rejected
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 401

    # Second token should still work
    resp = await client.get("/auth/me", headers={"Authorization": f"Bearer {second_token}"})
    assert resp.status_code == 200


# ── Account Lockout ───────────────────────────────


@pytest.mark.asyncio
async def test_account_lockout_after_failed_attempts(client: AsyncClient):
    """Account should be locked after 3 failed attempts (test config)."""
    await client.post(
        "/auth/register",
        json={"email": "lockout@test.com", "password": "password123", "name": "Lockout"},
    )

    # Fail 3 times
    for _ in range(3):
        resp = await client.post(
            "/auth/login",
            json={"email": "lockout@test.com", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    # 4th attempt should be locked out (429)
    resp = await client.post(
        "/auth/login",
        json={"email": "lockout@test.com", "password": "password123"},
    )
    assert resp.status_code == 429
    assert "locked" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_successful_login_clears_failed_attempts(client: AsyncClient):
    """Successful login should clear failed attempt counter."""
    await client.post(
        "/auth/register",
        json={"email": "clear@test.com", "password": "password123", "name": "Clear"},
    )

    # Fail twice (under threshold of 3)
    for _ in range(2):
        await client.post(
            "/auth/login",
            json={"email": "clear@test.com", "password": "wrongpassword"},
        )

    # Succeed — should clear attempts
    resp = await client.post(
        "/auth/login",
        json={"email": "clear@test.com", "password": "password123"},
    )
    assert resp.status_code == 200

    # Now fail twice — should NOT trigger lockout since counter was cleared
    for _ in range(2):
        await client.post(
            "/auth/login",
            json={"email": "clear@test.com", "password": "wrongpassword"},
        )

    # 3rd fail after clear — this records the 3rd attempt (401), lockout checks before recording
    resp = await client.post(
        "/auth/login",
        json={"email": "clear@test.com", "password": "wrongpassword"},
    )
    assert resp.status_code == 401  # 3rd attempt recorded but check saw only 2

    # 4th attempt should now be locked (check sees 3 recorded)
    resp = await client.post(
        "/auth/login",
        json={"email": "clear@test.com", "password": "password123"},
    )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_lockout_does_not_affect_other_users(client: AsyncClient):
    """Lockout on one account should not affect others."""
    await client.post(
        "/auth/register",
        json={"email": "locked@test.com", "password": "password123", "name": "Locked"},
    )
    await client.post(
        "/auth/register",
        json={"email": "unlocked@test.com", "password": "password123", "name": "Unlocked"},
    )

    # Lock out the first account
    for _ in range(3):
        await client.post(
            "/auth/login",
            json={"email": "locked@test.com", "password": "wrongpassword"},
        )

    # Second account should still work
    resp = await client.post(
        "/auth/login",
        json={"email": "unlocked@test.com", "password": "password123"},
    )
    assert resp.status_code == 200


# ── Concurrent Session Limit ─────────────────────


@pytest.mark.asyncio
async def test_concurrent_session_limit(client: AsyncClient):
    """Max 5 concurrent sessions — oldest revoked when limit exceeded."""
    await client.post(
        "/auth/register",
        json={"email": "sessions@test.com", "password": "password123", "name": "Sessions"},
    )

    # Collect refresh tokens from 6 logins
    refresh_tokens = []
    for _ in range(6):
        resp = await client.post(
            "/auth/login",
            json={"email": "sessions@test.com", "password": "password123"},
        )
        assert resp.status_code == 200
        refresh_tokens.append(resp.json()["refresh_token"])

    # The first refresh token (oldest) should have been revoked
    resp = await client.post("/auth/refresh", json={"refresh_token": refresh_tokens[0]})
    assert resp.status_code == 401

    # The latest refresh token should still work
    resp = await client.post("/auth/refresh", json={"refresh_token": refresh_tokens[-1]})
    assert resp.status_code == 200


# ── JTI in Access Tokens ─────────────────────────


@pytest.mark.asyncio
async def test_access_token_has_jti(client: AsyncClient):
    """Access tokens should contain a JTI claim."""
    import jwt

    reg = await client.post(
        "/auth/register",
        json={"email": "jti@test.com", "password": "password123", "name": "JTI"},
    )
    token = reg.json()["access_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "jti" in payload
    assert len(payload["jti"]) == 36  # UUID format
