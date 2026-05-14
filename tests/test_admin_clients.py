"""Admin CRUD + rotate + revoke endpoint tests for /auth/admin/clients."""

import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service.config import settings


async def _register_admin(client: AsyncClient) -> dict:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@admincli.example.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _register_pending_user(
    client: AsyncClient, *, email: str = "u@admincli.example.com"
) -> dict:
    """Register a second user — auto-admin only for the first registration."""
    resp = await client.post(
        "/auth/register",
        json={"email": email, "password": "password123", "name": "U"},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_create_returns_one_time_secret_and_persists_no_plaintext(client: AsyncClient):
    admin = await _register_admin(client)
    create_resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "Fusion", "description": "prod", "scopes": ["cuopt.solve"]},
    )
    assert create_resp.status_code == 201
    body = create_resp.json()
    assert body["client_id"].startswith("cli_")
    assert body["client_secret"].startswith("csk_")
    assert body["scopes"] == ["cuopt.solve"]

    # Subsequent reads must not include the plaintext secret.
    get_resp = await client.get(
        f"/auth/admin/clients/{body['id']}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert get_resp.status_code == 200
    assert "client_secret" not in get_resp.json()


@pytest.mark.asyncio
async def test_create_requires_admin(client: AsyncClient):
    await _register_admin(client)
    pending = await _register_pending_user(client)
    resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {pending['access_token']}"},
        json={"name": "x", "scopes": []},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_rejects_unauthenticated(client: AsyncClient):
    resp = await client.post("/auth/admin/clients", json={"name": "x", "scopes": []})
    # HTTPBearer with no credentials yields 401 from FastAPI's HTTPBearer.
    assert resp.status_code in {401, 403}


@pytest.mark.asyncio
async def test_list_returns_all_clients_for_admin(client: AsyncClient):
    admin = await _register_admin(client)
    for n in ["a", "b", "c"]:
        await client.post(
            "/auth/admin/clients",
            headers={"Authorization": f"Bearer {admin['access_token']}"},
            json={"name": n, "scopes": []},
        )
    resp = await client.get(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 3
    assert all("client_secret" not in r for r in rows)


@pytest.mark.asyncio
async def test_get_unknown_id_returns_404(client: AsyncClient):
    admin = await _register_admin(client)
    resp = await client.get(
        "/auth/admin/clients/99999",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_updates_mutable_fields(client: AsyncClient):
    admin = await _register_admin(client)
    create_resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "initial", "scopes": ["cuopt.view"]},
    )
    pk = create_resp.json()["id"]
    patch_resp = await client.patch(
        f"/auth/admin/clients/{pk}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "renamed", "scopes": ["cuopt.solve", "cuopt.view"]},
    )
    assert patch_resp.status_code == 200
    body = patch_resp.json()
    assert body["name"] == "renamed"
    assert body["scopes"] == ["cuopt.solve", "cuopt.view"]


@pytest.mark.asyncio
async def test_patch_unknown_id_returns_404(client: AsyncClient):
    admin = await _register_admin(client)
    resp = await client.patch(
        "/auth/admin/clients/99999",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "x"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_rotate_secret_returns_new_one_time_secret(client: AsyncClient):
    admin = await _register_admin(client)
    create_resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "x", "scopes": []},
    )
    pk = create_resp.json()["id"]
    original_secret = create_resp.json()["client_secret"]
    rotate_resp = await client.post(
        f"/auth/admin/clients/{pk}/rotate-secret",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert rotate_resp.status_code == 200
    new_secret = rotate_resp.json()["client_secret"]
    assert new_secret.startswith("csk_")
    assert new_secret != original_secret


@pytest.mark.asyncio
async def test_rotate_secret_unknown_id_returns_404(client: AsyncClient):
    admin = await _register_admin(client)
    resp = await client.post(
        "/auth/admin/clients/99999/rotate-secret",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_soft_deletes_and_subsequent_get_shows_revoked(client: AsyncClient):
    admin = await _register_admin(client)
    create_resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "x", "scopes": []},
    )
    pk = create_resp.json()["id"]
    delete_resp = await client.delete(
        f"/auth/admin/clients/{pk}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert delete_resp.status_code == 204
    get_resp = await client.get(
        f"/auth/admin/clients/{pk}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["is_active"] is False
    assert body["revoked_at"] is not None


@pytest.mark.asyncio
async def test_delete_unknown_id_returns_404(client: AsyncClient):
    admin = await _register_admin(client)
    resp = await client.delete(
        "/auth/admin/clients/99999",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_per_owner_cap_enforced(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "client_max_per_owner", 2)
    admin = await _register_admin(client)
    for n in range(2):
        ok = await client.post(
            "/auth/admin/clients",
            headers={"Authorization": f"Bearer {admin['access_token']}"},
            json={"name": f"c-{n}", "scopes": []},
        )
        assert ok.status_code == 201
    over = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "overflow", "scopes": []},
    )
    assert over.status_code == 409


@pytest.mark.asyncio
async def test_audit_log_records_client_principal_on_token_issue(client: AsyncClient):
    """Token issuance writes an audit row with actor_principal_type=client."""
    admin = await _register_admin(client)
    create_resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"name": "audited", "scopes": ["cuopt.view"]},
    )
    body = create_resp.json()
    token_resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": body["client_id"],
            "client_secret": body["client_secret"],
        },
    )
    assert token_resp.status_code == 200

    audit_resp = await client.get(
        "/auth/audit?event_type=oauth_token_issued",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert audit_resp.status_code == 200
    rows = audit_resp.json()["items"]
    issued = [r for r in rows if r["event_type"] == "oauth_token_issued"]
    assert issued, "expected at least one oauth_token_issued audit row"
    row = issued[0]
    assert row["actor_user_id"] is None
    assert row["actor_principal_type"] == "client"
    assert row["actor_principal_id"] == body["client_id"]
