"""Spec 003 acceptance tests for the OAuth2 token endpoint's scope handling.

Complements ``test_oauth_token.py`` (which already covers happy-path and
credential failures from spec 002). The cases here pin the lenient-default
behavior, the strict-mode flag, and the empty-intersection rejection.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.models import AuditLog, AuditResult


async def _register_admin(client: AsyncClient) -> dict:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@scopes.example.com", "password": "password123", "name": "Admin"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _create_service_account(
    client: AsyncClient,
    admin_token: str,
    *,
    scopes: list[str],
) -> dict:
    resp = await client.post(
        "/auth/admin/clients",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "Fusion-Test", "description": None, "scopes": scopes},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_lenient_partial_overlap_issues_intersection(client: AsyncClient, monkeypatch):
    """Lenient default: requesting a partially-allowed set yields the intersection."""
    monkeypatch.setattr(settings, "strict_scopes", False)
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
            "scope": "cuopt.view admin.users.manage",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "cuopt.view"


@pytest.mark.asyncio
async def test_lenient_empty_intersection_returns_invalid_scope(client: AsyncClient, monkeypatch):
    """Even under lenient mode, no overlap at all is an error — issuing an
    empty-scope token would silently neuter the caller's intent."""
    monkeypatch.setattr(settings, "strict_scopes", False)
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
async def test_strict_mode_partial_overlap_returns_invalid_scope(client: AsyncClient, monkeypatch):
    """Strict mode: any requested scope outside the allowed set fails the request."""
    monkeypatch.setattr(settings, "strict_scopes", True)
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
            "scope": "cuopt.solve admin.users.manage",
        },
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_scope"
    assert "admin.users.manage" in body["error_description"]


@pytest.mark.asyncio
async def test_strict_mode_full_overlap_succeeds(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "strict_scopes", True)
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
            "scope": "cuopt.solve cuopt.view",
        },
    )
    assert resp.status_code == 200
    assert set(resp.json()["scope"].split()) == {"cuopt.solve", "cuopt.view"}


@pytest.mark.asyncio
async def test_invalid_scope_writes_audit_log(client: AsyncClient, db_session, monkeypatch):
    """Spec 003 §Testing: oauth-token-endpoint invalid_scope writes an audit
    entry with ``AuditResult.failure`` and the offending scope on the target."""
    monkeypatch.setattr(settings, "strict_scopes", False)
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

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "oauth_token_invalid_scope")
    )
    entries = list(result.scalars().all())
    assert len(entries) == 1
    entry = entries[0]
    assert entry.result == AuditResult.failure
    assert "admin.users.manage" in (entry.target or "")
    assert entry.actor_principal_id == sa["client_id"]


@pytest.mark.asyncio
async def test_no_scope_requested_returns_full_allowed_set(client: AsyncClient, monkeypatch):
    """Spec 003 + RFC 6749 §3.3: omitting scope yields the client's full registered set."""
    monkeypatch.setattr(settings, "strict_scopes", False)
    admin = await _register_admin(client)
    sa = await _create_service_account(
        client, admin["access_token"], scopes=["cuopt.solve", "cuopt.view", "chat.use"]
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
    assert set(resp.json()["scope"].split()) == {"cuopt.solve", "cuopt.view", "chat.use"}
