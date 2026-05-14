"""Route-coverage tests for main.py — fills uncovered branches in SSO,
SCIM, providers, role assignments, permissions, and edge paths on
register/login/refresh.

These complement test_auth/test_phase*/test_collections rather than
duplicating their happy-path coverage. Each test targets a specific
uncovered line range.
"""

import logging
from unittest.mock import patch

import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service.config import settings

logger = logging.getLogger(__name__)


SCIM_HEADERS = {"Authorization": "Bearer test-scim-token"}


# ─── helpers ─────────────────────────────────────────────────────────────


async def _register_and_get_admin_token(client: AsyncClient) -> tuple[str, int]:
    """First registered user auto-promotes to admin (AUTH_AUTO_ADMIN_FIRST_USER=true)."""
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["access_token"], data["user"]["id"]


async def _register_second_user(client: AsyncClient, admin_token: str) -> tuple[str, int]:
    """Second user starts pending; admin promotes to 'user' via PATCH /auth/users/{id}."""
    resp = await client.post(
        "/auth/register",
        json={"email": "user@test.com", "password": "password123", "name": "User"},
    )
    user_id = resp.json()["user"]["id"]
    await client.patch(
        f"/auth/users/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "user"},
    )
    login_resp = await client.post(
        "/auth/login",
        json={"email": "user@test.com", "password": "password123"},
    )
    return login_resp.json()["access_token"], user_id


# ─── _require_local_auth gate (line 113) ─────────────────────────────────


@pytest.mark.asyncio
async def test_register_when_local_auth_disabled_403(client: AsyncClient):
    """Hitting /auth/register with local_auth_enabled=false → 403."""
    with patch.object(settings, "local_auth_enabled", False):
        resp = await client.post(
            "/auth/register",
            json={"email": "nope@test.com", "password": "password123", "name": "Nope"},
        )
    assert resp.status_code == 403
    assert "Local authentication is disabled" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_login_when_local_auth_disabled_403(client: AsyncClient):
    """Hitting /auth/login with local_auth_enabled=false → 403."""
    with patch.object(settings, "local_auth_enabled", False):
        resp = await client.post(
            "/auth/login",
            json={"email": "any@test.com", "password": "password123"},
        )
    assert resp.status_code == 403


# ─── /auth/login deactivated user (lines 203-204) ────────────────────────


@pytest.mark.asyncio
async def test_login_deactivated_user_403(client: AsyncClient):
    """Inactive user with valid creds → 403, not 401."""
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.post(
        "/auth/register",
        json={"email": "deact@test.com", "password": "password123", "name": "Deact"},
    )
    user_id = resp.json()["user"]["id"]
    await client.patch(
        f"/auth/users/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "user", "is_active": False},
    )
    resp = await client.post(
        "/auth/login",
        json={"email": "deact@test.com", "password": "password123"},
    )
    assert resp.status_code == 403
    assert "deactivated" in resp.json()["detail"].lower()


# ─── /auth/refresh edge paths (lines 219-241) ────────────────────────────


@pytest.mark.asyncio
async def test_refresh_with_invalid_token_401(client: AsyncClient):
    resp = await client.post(
        "/auth/refresh",
        json={"refresh_token": "not-a-real-token"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_after_user_deactivated_401(client: AsyncClient):
    """Refresh with a token issued to a user that's since been deactivated."""
    admin_token, _ = await _register_and_get_admin_token(client)
    user_token, user_id = await _register_second_user(client, admin_token)
    # Issue a fresh refresh token for the user
    login = await client.post(
        "/auth/login",
        json={"email": "user@test.com", "password": "password123"},
    )
    refresh = login.json()["refresh_token"]
    # Deactivate the user
    await client.patch(
        f"/auth/users/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False},
    )
    resp = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


# ─── /auth/users/{id} PATCH 404 + name update (line 313) ─────────────────


@pytest.mark.asyncio
async def test_patch_user_not_found_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.patch(
        "/auth/users/9999",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "user"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_user_name_only(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    _, user_id = await _register_second_user(client, admin_token)
    resp = await client.patch(
        f"/auth/users/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "Renamed"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"


# ─── /auth/permissions list + check 404 (lines 597-598, 612) ─────────────


@pytest.mark.asyncio
async def test_list_permissions_admin(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.get(
        "/auth/permissions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_check_permission_user_not_found(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.post(
        "/auth/permissions/check",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"user_id": 9999, "permission": "users:read"},
    )
    assert resp.status_code == 404


# ─── /auth/users/{id}/roles full lifecycle (lines 632, 660-683, 705-712) ──


@pytest.mark.asyncio
async def test_user_roles_assign_and_remove(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    _, user_id = await _register_second_user(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # List roles for new user (empty)
    resp = await client.get(f"/auth/users/{user_id}/roles", headers=headers)
    assert resp.status_code == 200
    initial = resp.json()

    # Need a role to assign — list existing
    roles_resp = await client.get("/auth/roles", headers=headers)
    assert roles_resp.status_code == 200
    roles = roles_resp.json()
    assert roles, "Expected seeded system roles"
    role_id = roles[0]["id"]

    # Assign
    assign_resp = await client.post(
        f"/auth/users/{user_id}/roles",
        headers=headers,
        json={"role_id": role_id},
    )
    assert assign_resp.status_code == 201
    assignment_id = assign_resp.json()["id"]

    # List again — now includes
    resp = await client.get(f"/auth/users/{user_id}/roles", headers=headers)
    assert len(resp.json()) == len(initial) + 1

    # Remove
    del_resp = await client.delete(
        f"/auth/users/{user_id}/roles/{assignment_id}",
        headers=headers,
    )
    assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_assign_role_to_unknown_user_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.post(
        "/auth/users/9999/roles",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role_id": 1},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_assign_unknown_role_to_user_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    _, user_id = await _register_second_user(client, admin_token)
    resp = await client.post(
        f"/auth/users/{user_id}/roles",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role_id": 99999},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_remove_unknown_role_assignment_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    _, user_id = await _register_second_user(client, admin_token)
    resp = await client.delete(
        f"/auth/users/{user_id}/roles/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


# ─── /auth/providers GET/PATCH/DELETE 404 + read-by-id (lines 754-806) ────


async def _create_oidc_provider(client: AsyncClient, admin_token: str, slug: str = "okta") -> int:
    # All four endpoint override URLs are supplied so the auth-service skips
    # the OIDC discovery probe at create time (tests don't exchange real
    # codes; the discovery surface is exercised separately in test_sso_service).
    resp = await client.post(
        "/auth/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "type": "oidc",
            "name": "Test OIDC",
            "slug": slug,
            "config": {
                "issuer": "https://idp.example.com",
                "client_id": "test-client",
                "client_secret": "test-secret",
                "authorize_url": "https://idp.example.com/authorize",
                "token_url": "https://idp.example.com/token",
                "userinfo_url": "https://idp.example.com/userinfo",
                "jwks_url": "https://idp.example.com/jwks",
                "scope": "openid email profile",
            },
            "is_active": True,
            "priority": 10,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_get_provider_by_id_and_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    pid = await _create_oidc_provider(client, admin_token)

    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await client.get(f"/auth/providers/{pid}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["slug"] == "okta"

    resp = await client.get("/auth/providers/9999", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_provider_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.patch(
        "/auth/providers/9999",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "Renamed"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_provider_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.delete(
        "/auth/providers/9999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


# ─── /auth/providers/{id}/mappings (lines 812-885) ────────────────────────


@pytest.mark.asyncio
async def test_create_claim_mapping_provider_not_found_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.post(
        "/auth/providers/9999/mappings",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "claim_key": "groups",
            "claim_value_pattern": "admins",
            "role_id": 1,
            "priority": 10,
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_claim_mapping_role_not_found_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    pid = await _create_oidc_provider(client, admin_token)
    resp = await client.post(
        f"/auth/providers/{pid}/mappings",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "claim_key": "groups",
            "claim_value_pattern": "admins",
            "role_id": 99999,
            "priority": 10,
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_claim_mapping_404(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    pid = await _create_oidc_provider(client, admin_token)
    resp = await client.delete(
        f"/auth/providers/{pid}/mappings/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


# ─── /auth/sso/{slug}/authorize (lines 953-1006) ─────────────────────────


@pytest.mark.asyncio
async def test_sso_authorize_oidc(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    await _create_oidc_provider(client, admin_token, slug="okta")
    resp = await client.get(
        "/auth/sso/okta/authorize",
        params={"redirect_uri": "http://localhost:3000/auth/callback/okta"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider_slug"] == "okta"
    assert "authorize_url" in body
    assert "state" in body
    assert "https://idp.example.com" in body["authorize_url"]
    assert "client_id=test-client" in body["authorize_url"]


@pytest.mark.asyncio
async def test_sso_authorize_saml(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    resp = await client.post(
        "/auth/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "type": "saml",
            "name": "Test SAML",
            "slug": "saml1",
            "config": {"login_url": "https://idp.example.com/saml/sso"},
            "is_active": True,
            "priority": 10,
        },
    )
    assert resp.status_code == 201
    resp = await client.get(
        "/auth/sso/saml1/authorize",
        params={"redirect_uri": "http://localhost:3000/auth/callback/saml1"},
    )
    assert resp.status_code == 200
    assert resp.json()["authorize_url"] == "https://idp.example.com/saml/sso"


@pytest.mark.asyncio
async def test_sso_authorize_unknown_slug_404(client: AsyncClient):
    resp = await client.get(
        "/auth/sso/nonexistent/authorize",
        params={"redirect_uri": "http://localhost:3000/cb"},
    )
    assert resp.status_code == 404


# ─── /auth/sso/{slug}/token (lines 1009-1051) — mocked code exchange ──────


@pytest.mark.asyncio
async def test_sso_token_unknown_slug_404(client: AsyncClient):
    resp = await client.post(
        "/auth/sso/nonexistent/token",
        json={
            "code": "abc",
            "redirect_uri": "http://localhost:3000/cb",
            "state": "any-state",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sso_token_exchange_jit_provisions(client: AsyncClient):
    """Exchange-code → JIT path: mint state via /authorize, mock the IdP
    exchange, and verify the user is provisioned and tokens are issued."""
    admin_token, _ = await _register_and_get_admin_token(client)
    await _create_oidc_provider(client, admin_token, slug="oidc-jit")

    auth_resp = await client.get(
        "/auth/sso/oidc-jit/authorize",
        params={"redirect_uri": "http://localhost:3000/cb"},
    )
    assert auth_resp.status_code == 200
    state = auth_resp.json()["state"]

    async def _fake_exchange(provider, code, redirect_uri, *, expected_nonce=None):
        # The route passes the persisted nonce through to exchange — return a
        # successfully-verified claim set as if the IdP had signed it.
        return {
            "sub": "external-123",
            "email": "ext@example.com",
            "name": "External User",
        }

    with patch(
        "accelerator_pack_auth_service.sso_service.exchange_oidc_code",
        side_effect=_fake_exchange,
    ):
        resp = await client.post(
            "/auth/sso/oidc-jit/token",
            json={
                "code": "abc",
                "redirect_uri": "http://localhost:3000/cb",
                "state": state,
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "access_token" in body
    assert body["user"]["email"] == "ext@example.com"


# ─── SCIM endpoints (lines 1183-1342) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_scim_service_provider_config(client: AsyncClient):
    resp = await client.get("/scim/v2/ServiceProviderConfig", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert "schemas" in resp.json()


@pytest.mark.asyncio
async def test_scim_schemas(client: AsyncClient):
    resp = await client.get("/scim/v2/Schemas", headers=SCIM_HEADERS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_scim_resource_types(client: AsyncClient):
    resp = await client.get("/scim/v2/ResourceTypes", headers=SCIM_HEADERS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_scim_users_list(client: AsyncClient):
    # Seed one user so list isn't empty (also exercises path with non-empty Resources)
    await client.post(
        "/auth/register",
        json={"email": "scim1@test.com", "password": "password123", "name": "Scim One"},
    )
    resp = await client.get("/scim/v2/Users", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] >= 1
    assert body["Resources"][0]["userName"]


@pytest.mark.asyncio
async def test_scim_user_crud(client: AsyncClient):
    create = await client.post(
        "/scim/v2/Users",
        headers=SCIM_HEADERS,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim.created@example.com",
            "name": {"givenName": "Scim", "familyName": "Created"},
            "emails": [{"value": "scim.created@example.com", "primary": True}],
            "active": True,
        },
    )
    assert create.status_code == 201, create.text
    user_id = create.json()["id"]

    # Get
    got = await client.get(f"/scim/v2/Users/{user_id}", headers=SCIM_HEADERS)
    assert got.status_code == 200

    # Put (replace)
    put = await client.put(
        f"/scim/v2/Users/{user_id}",
        headers=SCIM_HEADERS,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim.created@example.com",
            "name": {"givenName": "Scim", "familyName": "Renamed"},
            "active": True,
        },
    )
    assert put.status_code == 200

    # Delete (soft — deactivates)
    delete = await client.delete(f"/scim/v2/Users/{user_id}", headers=SCIM_HEADERS)
    assert delete.status_code == 204


@pytest.mark.asyncio
async def test_scim_user_not_found(client: AsyncClient):
    for path in [
        "/scim/v2/Users/9999",
    ]:
        resp = await client.get(path, headers=SCIM_HEADERS)
        assert resp.status_code == 404, path
    resp = await client.put(
        "/scim/v2/Users/9999",
        headers=SCIM_HEADERS,
        json={"userName": "x"},
    )
    assert resp.status_code == 404
    resp = await client.delete("/scim/v2/Users/9999", headers=SCIM_HEADERS)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_scim_groups_crud_and_not_found(client: AsyncClient):
    # List (empty initially)
    resp = await client.get("/scim/v2/Groups", headers=SCIM_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["totalResults"] == 0

    # Create
    create = await client.post(
        "/scim/v2/Groups",
        headers=SCIM_HEADERS,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "scim-group-1",
        },
    )
    assert create.status_code == 201, create.text
    group_id = create.json()["id"]

    # List non-empty
    resp = await client.get("/scim/v2/Groups", headers=SCIM_HEADERS)
    assert resp.json()["totalResults"] == 1

    # Get
    got = await client.get(f"/scim/v2/Groups/{group_id}", headers=SCIM_HEADERS)
    assert got.status_code == 200

    # Put
    put = await client.put(
        f"/scim/v2/Groups/{group_id}",
        headers=SCIM_HEADERS,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "scim-group-renamed",
        },
    )
    assert put.status_code == 200

    # Delete
    delete = await client.delete(f"/scim/v2/Groups/{group_id}", headers=SCIM_HEADERS)
    assert delete.status_code == 204

    # Not-found paths
    resp = await client.get("/scim/v2/Groups/9999", headers=SCIM_HEADERS)
    assert resp.status_code == 404
    resp = await client.put(
        "/scim/v2/Groups/9999",
        headers=SCIM_HEADERS,
        json={"displayName": "x"},
    )
    assert resp.status_code == 404
    resp = await client.delete("/scim/v2/Groups/9999", headers=SCIM_HEADERS)
    assert resp.status_code == 404


# ─── Groups (lines 1057-1342) ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_groups_crud(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # List (empty)
    resp = await client.get("/auth/groups", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []

    # Create
    create = await client.post(
        "/auth/groups",
        headers=headers,
        json={"name": "engineering", "display_name": "Engineering"},
    )
    assert create.status_code == 201
    group_id = create.json()["id"]

    # List non-empty
    resp = await client.get("/auth/groups", headers=headers)
    assert len(resp.json()) == 1

    # Add member
    _, user_id = await _register_second_user(client, admin_token)
    add_member = await client.post(
        f"/auth/groups/{group_id}/members",
        headers=headers,
        json={"user_id": user_id},
    )
    assert add_member.status_code == 201

    # List members
    members = await client.get(f"/auth/groups/{group_id}/members", headers=headers)
    assert members.status_code == 200
    assert len(members.json()) >= 1

    # Remove member
    rm = await client.delete(
        f"/auth/groups/{group_id}/members/{user_id}",
        headers=headers,
    )
    assert rm.status_code in (200, 204)


@pytest.mark.asyncio
async def test_groups_non_admin_403(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    user_token, _ = await _register_second_user(client, admin_token)
    resp = await client.get(
        "/auth/groups",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403


# ─── /auth/admin/status edge: requires admin (line 1402 already covered;
# this exercises stats accumulation with non-zero counts to hit all
# stat-aggregation expressions) ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_admin_status_with_seeded_data(client: AsyncClient):
    admin_token, _ = await _register_and_get_admin_token(client)
    await _register_second_user(client, admin_token)
    await _create_oidc_provider(client, admin_token, slug="status-oidc")
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post("/auth/groups", headers=headers, json={"name": "g1"})

    resp = await client.get("/auth/admin/status", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["stats"]["total_users"] >= 2
    assert body["stats"]["identity_providers"] >= 1
    assert body["stats"]["groups"] >= 1
