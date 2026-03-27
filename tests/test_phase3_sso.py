"""Tests for Phase 3: SSO — providers, claim mappings, JIT provisioning, SSO callback."""

import pytest
from httpx import AsyncClient


async def _get_admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return resp.json()["access_token"]


# ── Provider CRUD ────────────────────────────────


@pytest.mark.asyncio
async def test_create_oidc_provider(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.post(
        "/auth/providers",
        json={
            "type": "oidc",
            "name": "Test OIDC",
            "slug": "test-oidc",
            "config": {
                "client_id": "test-client",
                "client_secret": "test-secret",
                "issuer": "https://idp.example.com",
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["type"] == "oidc"
    assert data["slug"] == "test-oidc"
    assert data["config"]["client_id"] == "test-client"


@pytest.mark.asyncio
async def test_create_saml_provider(client: AsyncClient):
    token = await _get_admin_token(client)
    resp = await client.post(
        "/auth/providers",
        json={
            "type": "saml",
            "name": "Test SAML",
            "slug": "test-saml",
            "config": {"entity_id": "https://sp.example.com"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["type"] == "saml"


@pytest.mark.asyncio
async def test_create_duplicate_slug_fails(client: AsyncClient):
    token = await _get_admin_token(client)
    await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "First", "slug": "dup-slug", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Second", "slug": "dup-slug", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_list_providers(client: AsyncClient):
    token = await _get_admin_token(client)
    await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "P1", "slug": "p1", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.get("/auth/providers", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


@pytest.mark.asyncio
async def test_update_provider(client: AsyncClient):
    token = await _get_admin_token(client)
    create = await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Old Name", "slug": "update-me", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    pid = create.json()["id"]

    resp = await client.patch(
        f"/auth/providers/{pid}",
        json={"name": "New Name", "is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_delete_provider(client: AsyncClient):
    token = await _get_admin_token(client)
    create = await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Delete Me", "slug": "delete-me", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    pid = create.json()["id"]

    resp = await client.delete(
        f"/auth/providers/{pid}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 204

    resp = await client.get(f"/auth/providers/{pid}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404


# ── Claim Mappings ───────────────────────────────


@pytest.mark.asyncio
async def test_create_and_list_claim_mapping(client: AsyncClient):
    token = await _get_admin_token(client)

    # Create provider
    prov = await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Mapper", "slug": "mapper", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    pid = prov.json()["id"]

    # Get a role to map to
    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    user_role = next(r for r in roles.json() if r["name"] == "user")

    # Create mapping
    resp = await client.post(
        f"/auth/providers/{pid}/mappings",
        json={
            "claim_key": "groups",
            "claim_value_pattern": "engineering",
            "role_id": user_role["id"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["claim_key"] == "groups"

    # List
    resp = await client.get(
        f"/auth/providers/{pid}/mappings", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_delete_claim_mapping(client: AsyncClient):
    token = await _get_admin_token(client)

    prov = await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Del Map", "slug": "del-map", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    pid = prov.json()["id"]

    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    reader_role = next(r for r in roles.json() if r["name"] == "reader")

    mapping = await client.post(
        f"/auth/providers/{pid}/mappings",
        json={
            "claim_key": "role",
            "claim_value_pattern": "viewer",
            "role_id": reader_role["id"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    mid = mapping.json()["id"]

    resp = await client.delete(
        f"/auth/providers/{pid}/mappings/{mid}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


# ── SSO Callback / JIT Provisioning ──────────────


@pytest.mark.asyncio
async def test_sso_callback_creates_new_user(client: AsyncClient):
    """SSO callback should JIT-provision a new user and return tokens."""
    token = await _get_admin_token(client)

    # Create an active provider
    await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "SSO Test", "slug": "sso-test", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )

    # Simulate SSO callback
    resp = await client.post(
        "/auth/sso/callback",
        json={
            "provider_slug": "sso-test",
            "external_id": "ext-user-123",
            "email": "sso-user@example.com",
            "name": "SSO User",
            "claims": {"groups": ["engineering"]},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "sso-user@example.com"
    assert data["user"]["role"] == "user"  # SSO default role


@pytest.mark.asyncio
async def test_sso_callback_links_existing_user(client: AsyncClient):
    """SSO callback for existing email should link accounts, not create duplicate."""
    token = await _get_admin_token(client)

    await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Link Test", "slug": "link-test", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )

    # First SSO login
    resp1 = await client.post(
        "/auth/sso/callback",
        json={
            "provider_slug": "link-test",
            "external_id": "ext-link-1",
            "email": "link@example.com",
            "name": "Link User",
        },
    )
    user_id_1 = resp1.json()["user"]["id"]

    # Second SSO login with same external_id
    resp2 = await client.post(
        "/auth/sso/callback",
        json={
            "provider_slug": "link-test",
            "external_id": "ext-link-1",
            "email": "link@example.com",
            "name": "Link User",
        },
    )
    user_id_2 = resp2.json()["user"]["id"]

    # Same user
    assert user_id_1 == user_id_2


@pytest.mark.asyncio
async def test_sso_callback_applies_claim_mappings(client: AsyncClient):
    """SSO callback should apply claim-to-role mappings."""
    token = await _get_admin_token(client)

    prov = await client.post(
        "/auth/providers",
        json={"type": "oidc", "name": "Claims Test", "slug": "claims-test", "config": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    pid = prov.json()["id"]

    # Get reader role
    roles = await client.get("/auth/roles", headers={"Authorization": f"Bearer {token}"})
    reader_role = next(r for r in roles.json() if r["name"] == "reader")

    # Map "department=finance" → reader role
    await client.post(
        f"/auth/providers/{pid}/mappings",
        json={
            "claim_key": "department",
            "claim_value_pattern": "finance",
            "role_id": reader_role["id"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    # SSO callback with matching claim
    resp = await client.post(
        "/auth/sso/callback",
        json={
            "provider_slug": "claims-test",
            "external_id": "finance-user-1",
            "email": "finance@example.com",
            "name": "Finance User",
            "claims": {"department": "finance"},
        },
    )
    assert resp.status_code == 200
    user_id = resp.json()["user"]["id"]

    # Verify role was assigned
    user_roles = await client.get(
        f"/auth/users/{user_id}/roles", headers={"Authorization": f"Bearer {token}"}
    )
    assert user_roles.status_code == 200
    role_names = [r["role_name"] for r in user_roles.json()]
    assert "reader" in role_names


@pytest.mark.asyncio
async def test_sso_callback_inactive_provider_fails(client: AsyncClient):
    """SSO callback should fail for inactive providers."""
    token = await _get_admin_token(client)

    prov = await client.post(
        "/auth/providers",
        json={
            "type": "oidc",
            "name": "Inactive",
            "slug": "inactive",
            "config": {},
            "is_active": False,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert prov.status_code == 201

    resp = await client.post(
        "/auth/sso/callback",
        json={
            "provider_slug": "inactive",
            "external_id": "ext-1",
            "email": "x@example.com",
            "name": "X",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sso_callback_unknown_provider_fails(client: AsyncClient):
    """SSO callback should fail for unknown provider slugs."""
    resp = await client.post(
        "/auth/sso/callback",
        json={
            "provider_slug": "nonexistent",
            "external_id": "ext-1",
            "email": "x@example.com",
            "name": "X",
        },
    )
    assert resp.status_code == 404
