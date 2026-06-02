"""Tests for service-account (client_credentials) support in /auth/validate
and the env-seeded bootstrap client.

Downstream services (e.g. OGX/llama-stack) validate every request by POSTing
``{"api_key": <jwt>}`` to /auth/validate. Service-account tokens carry
``sub="client:<client_id>"`` / ``principal_type="client"``, which the legacy
user path (``int(sub)``) could not handle. These tests lock in that a client
token validates to a ``client:<id>`` principal, and that the bootstrap seeder
is idempotent + honors secret rotation.
"""

import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service import clients


async def _register_admin(client: AsyncClient) -> dict:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@validate.example.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_service_account(client: AsyncClient, admin_token: str) -> dict:
    resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "etl-ingestor", "description": None, "scopes": []},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_validate_accepts_client_credentials_token(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])

    tok = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert tok.status_code == 200, tok.text
    access_token = tok.json()["access_token"]

    resp = await client.post("/auth/validate", json={"api_key": access_token})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["principal"] == f"client:{sa['client_id']}"
    assert "scope" in body["attributes"]


@pytest.mark.asyncio
async def test_validate_rejects_revoked_client(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    tok = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    access_token = tok.json()["access_token"]

    # Revoke via the admin API (soft-delete: is_active=false), then the token
    # must no longer validate even though its signature/exp are still good.
    revoke = await client.delete(
        f"/auth/admin/clients/{sa['id']}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert revoke.status_code == 204, revoke.text

    resp = await client.post("/auth/validate", json={"api_key": access_token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_seed_bootstrap_client_idempotent_and_rotates(db_session):
    cid = "cli_bootstrap_test"
    first = await clients.seed_bootstrap_client(
        db_session, client_id=cid, client_secret="secret-one", scopes=["collections:read"]
    )
    assert first.client_id == cid
    assert first.owner_user_id is None
    assert clients.verify_secret("secret-one", first.client_secret_hash)

    # Second boot with a rotated secret: same row, new hash, reactivated.
    second = await clients.seed_bootstrap_client(
        db_session, client_id=cid, client_secret="secret-two", scopes=["collections:read"]
    )
    assert second.id == first.id
    assert second.is_active is True
    assert clients.verify_secret("secret-two", second.client_secret_hash)
    assert not clients.verify_secret("secret-one", second.client_secret_hash)
