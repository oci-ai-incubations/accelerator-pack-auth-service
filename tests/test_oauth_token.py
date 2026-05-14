"""Endpoint tests for POST /auth/oauth/token (RFC 6749 §4.4 client_credentials).

Each test starts by registering an admin user, creating a service account
through the admin API, then exercising the token endpoint with various
credential and scope shapes. The spec's full acceptance matrix is covered
here.
"""

import base64
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service.config import settings


async def _register_admin(client: AsyncClient) -> dict:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@oauth.example.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _create_service_account(
    client: AsyncClient,
    admin_token: str,
    *,
    name: str = "Fusion-ERP",
    scopes: list[str] | None = None,
    expires_at: str | None = None,
) -> dict:
    payload: dict = {"name": name, "description": None, "scopes": scopes or []}
    if expires_at is not None:
        payload["expires_at"] = expires_at
    resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin_token}"},
        json=payload,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_token_happy_path_form_credentials(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(
        client, admin["access_token"], scopes=["cuopt.solve", "cuopt.view"]
    )
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == settings.client_token_expire_minutes * 60
    assert body["access_token"]
    assert set(body["scope"].split()) == {"cuopt.solve", "cuopt.view"}


@pytest.mark.asyncio
async def test_token_basic_auth_flavor_works_identically(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"], scopes=["cuopt.view"])
    encoded = base64.b64encode(f"{sa['client_id']}:{sa['client_secret']}".encode()).decode()
    resp = await client.post(
        "/auth/oauth/token",
        headers={"Authorization": f"Basic {encoded}"},
        data={"grant_type": "client_credentials"},
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


@pytest.mark.asyncio
async def test_token_rejects_when_basic_and_form_both_present(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"], scopes=["cuopt.view"])
    encoded = base64.b64encode(f"{sa['client_id']}:{sa['client_secret']}".encode()).decode()
    resp = await client.post(
        "/auth/oauth/token",
        headers={"Authorization": f"Basic {encoded}"},
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_token_bad_client_id_returns_invalid_client(client: AsyncClient):
    admin = await _register_admin(client)
    await _create_service_account(client, admin["access_token"])
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "cli_does_not_exist",
            "client_secret": "csk_anything",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_bad_client_secret_returns_same_error_as_bad_id(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": "csk_wrong",
        },
    )
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "invalid_client"
    # Identical error description — no enumeration signal between bad id vs bad secret.
    assert body["error_description"] == "Client authentication failed"


@pytest.mark.asyncio
async def test_token_revoked_client_returns_invalid_client(client: AsyncClient):
    """DELETE sets both is_active=False AND revoked_at — the 'revoked' branch."""
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    # Revoke via DELETE soft-delete path.
    resp = await client.delete(
        f"/auth/admin/clients/{sa['id']}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert resp.status_code == 204
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_disabled_only_client_returns_invalid_client(client: AsyncClient, db_session):
    """PATCH is_active=False leaves revoked_at=None — the 'disabled, not revoked' branch.

    Separate coverage of the ``is_active=False`` rejection: DELETE bundles
    both flags, so a regression that started checking ``revoked_at`` alone
    would silently allow a disabled-but-not-revoked client to mint tokens.
    """
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import ServiceAccount

    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    patch_resp = await client.patch(
        f"/auth/admin/clients/{sa['id']}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"is_active": False},
    )
    assert patch_resp.status_code == 200
    # PATCH stamps revoked_at as a side effect (clients.update_client). The
    # spec also documents disabled-vs-revoked as conceptually distinct, so
    # clear revoked_at via the shared test session to force the pure-disabled
    # branch.
    result = await db_session.execute(
        select(ServiceAccount).where(ServiceAccount.client_id == sa["client_id"])
    )
    account = result.scalar_one()
    account.revoked_at = None
    await db_session.commit()

    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_expired_client_returns_invalid_client(client: AsyncClient, db_session):
    """A client whose expires_at lies in the past must yield invalid_client.

    The create schema now rejects past expiry (H2), so seed with a valid
    future date and rewind ``expires_at`` via the shared test session to
    simulate time having passed.
    """
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import ServiceAccount

    admin = await _register_admin(client)
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    sa = await _create_service_account(
        client, admin["access_token"], scopes=["cuopt.view"], expires_at=future
    )
    result = await db_session.execute(
        select(ServiceAccount).where(ServiceAccount.client_id == sa["client_id"])
    )
    account = result.scalar_one()
    account.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_wrong_grant_type_returns_unsupported_grant_type(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "password",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_token_missing_credentials_returns_invalid_client(client: AsyncClient):
    resp = await client.post(
        "/auth/oauth/token",
        data={"grant_type": "client_credentials"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_token_no_scope_requested_issues_full_allowed_set(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(
        client, admin["access_token"], scopes=["cuopt.solve", "cuopt.view"]
    )
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 200
    assert set(resp.json()["scope"].split()) == {"cuopt.solve", "cuopt.view"}


@pytest.mark.asyncio
async def test_token_subset_scope_requested_issues_only_that_subset(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(
        client, admin["access_token"], scopes=["cuopt.solve", "cuopt.view"]
    )
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
            "scope": "cuopt.view",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "cuopt.view"


@pytest.mark.asyncio
async def test_token_invalid_scope_returns_invalid_scope(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"], scopes=["cuopt.view"])
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
            "scope": "admin.users.manage",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_token_disabled_master_switch_returns_unsupported_grant_type(
    client: AsyncClient, monkeypatch
):
    """RFC 6749 §5.2 maps ``unsupported_grant_type`` to 400; the master-switch
    response follows the standard rather than 503 (transient).
    """
    monkeypatch.setattr(settings, "client_credentials_enabled", False)
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "cli_x",
            "client_secret": "csk_x",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_token_claims_carry_principal_type_client_and_client_id(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"], scopes=["cuopt.view"])
    resp = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp.status_code == 200
    access_token = resp.json()["access_token"]
    claims = jwt.decode(access_token, options={"verify_signature": False})
    assert claims["principal_type"] == "client"
    assert claims["sub"] == f"client:{sa['client_id']}"
    assert claims["client_id"] == sa["client_id"]
    assert claims["scope"] == "cuopt.view"
    assert settings.pack in claims["aud"]
    assert claims["iss"] == settings.issuer_url


@pytest.mark.asyncio
async def test_token_rotated_secret_invalidates_old_secret(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    rotate_resp = await client.post(
        f"/auth/admin/clients/{sa['id']}/rotate-secret",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert rotate_resp.status_code == 200
    new_secret = rotate_resp.json()["client_secret"]
    assert new_secret != sa["client_secret"]

    # Old secret: invalid_client.
    resp_old = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )
    assert resp_old.status_code == 401
    assert resp_old.json()["error"] == "invalid_client"

    # New secret works.
    resp_new = await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": new_secret,
        },
    )
    assert resp_new.status_code == 200


@pytest.mark.asyncio
async def test_token_unknown_client_pays_bcrypt_cost_for_timing_parity(client: AsyncClient):
    """Smoke test that unknown-client and known-bad-secret response times are similar.

    Without the parity hash, an unknown client_id returns ~instantly while a
    bad-secret roundtrip pays the ~250ms bcrypt cost — an attacker can
    enumerate valid client_ids over the network. Allow a 2x ratio: both
    paths must pay bcrypt, but jitter (test parallelism, GC) makes tighter
    bounds flaky in CI.
    """
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])

    # Warm-up call so the first-time dummy-hash computation doesn't skew the
    # measured window.
    await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "cli_warmup_unknown",
            "client_secret": "csk_anything",
        },
    )

    start = time.monotonic()
    await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "cli_does_not_exist_xyz",
            "client_secret": "csk_anything",
        },
    )
    unknown_elapsed = time.monotonic() - start

    start = time.monotonic()
    await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": "csk_wrong_secret_value",
        },
    )
    bad_secret_elapsed = time.monotonic() - start

    # Both branches pay bcrypt; the ratio shouldn't be more than 2x in
    # either direction. Pure smoke — exact bcrypt timings are machine-
    # dependent and not the point.
    ratio = max(unknown_elapsed, bad_secret_elapsed) / min(unknown_elapsed, bad_secret_elapsed)
    assert ratio < 2.0, (
        f"timing parity broken: unknown={unknown_elapsed:.3f}s "
        f"bad_secret={bad_secret_elapsed:.3f}s ratio={ratio:.2f}"
    )


@pytest.mark.asyncio
async def test_token_updates_last_used_metadata(client: AsyncClient):
    admin = await _register_admin(client)
    sa = await _create_service_account(client, admin["access_token"])
    pre_resp = await client.get(
        f"/auth/admin/clients/{sa['id']}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert pre_resp.json()["last_used_at"] is None

    await client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": sa["client_id"],
            "client_secret": sa["client_secret"],
        },
    )

    post_resp = await client.get(
        f"/auth/admin/clients/{sa['id']}",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert post_resp.json()["last_used_at"] is not None
