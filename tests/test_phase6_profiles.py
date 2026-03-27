"""Tests for Phase 6: configuration profiles and admin dashboard."""

import pytest
from httpx import AsyncClient


async def _get_admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return resp.json()["access_token"]


# ── Admin Dashboard ──────────────────────────────


@pytest.mark.asyncio
async def test_admin_status_endpoint(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.get("/auth/admin/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == "1.0.0"
    assert "features" in data
    assert "stats" in data
    assert data["stats"]["total_users"] >= 1
    assert data["stats"]["active_users"] >= 1


@pytest.mark.asyncio
async def test_admin_status_shows_features(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.get("/auth/admin/status", headers={"Authorization": f"Bearer {token}"})
    features = resp.json()["features"]
    assert "local_auth" in features
    assert "oidc" in features
    assert "saml" in features
    assert "scim" in features
    assert "audit" in features


@pytest.mark.asyncio
async def test_admin_status_requires_admin(client: AsyncClient):
    await _get_admin_token(client)
    user = await client.post(
        "/auth/register",
        json={"email": "user@test.com", "password": "password123", "name": "User"},
    )
    user_token = user.json()["access_token"]
    resp = await client.get("/auth/admin/status", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403


# ── Profile Presets ──────────────────────────────


def test_profile_presets_exist():
    from accelerator_pack_auth_service.config import PROFILE_PRESETS

    assert "minimal" in PROFILE_PRESETS
    assert "standard" in PROFILE_PRESETS
    assert "enterprise" in PROFILE_PRESETS


def test_minimal_profile_disables_sso():
    from accelerator_pack_auth_service.config import PROFILE_PRESETS

    minimal = PROFILE_PRESETS["minimal"]
    assert minimal["oidc_enabled"] is False
    assert minimal["saml_enabled"] is False
    assert minimal["scim_enabled"] is False


def test_enterprise_profile_enables_all():
    from accelerator_pack_auth_service.config import PROFILE_PRESETS

    enterprise = PROFILE_PRESETS["enterprise"]
    assert enterprise["oidc_enabled"] is True
    assert enterprise["saml_enabled"] is True
    assert enterprise["scim_enabled"] is True
    assert enterprise["audit_enabled"] is True


# ── Version ──────────────────────────────────────


@pytest.mark.asyncio
async def test_health_shows_v1(client: AsyncClient):
    resp = await client.get("/auth/health")
    assert resp.json()["version"] == "1.0.0"
