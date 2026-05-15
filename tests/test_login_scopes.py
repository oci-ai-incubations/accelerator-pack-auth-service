"""Spec 003 acceptance tests for /auth/login with the scope body field.

Login is the user-facing scope-grant path — the equivalent of /oauth/token
for human callers. The token's ``scope`` claim is the granted set
(intersection of requested-vs-role-expansion).
"""

import base64
import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.models import AuditLog, AuditResult


def _decode_scope_claim(access_token: str) -> list[str]:
    """Pull the unsigned ``scope`` claim out of a JWT for assertion."""
    payload_b64 = access_token.split(".")[1] + "=="
    claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    raw = claims.get("scope", "")
    return raw.split() if raw else []


async def _register(client: AsyncClient, email: str) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": email, "password": "password123", "name": email.split("@")[0]},
    )
    assert resp.status_code == 201
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_login_no_scope_carries_role_expansion(client: AsyncClient, monkeypatch):
    """Default cuopt admin gets the wildcard-expanded full permission set."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    await _register(client, "first@scopes.example.com")
    resp = await client.post(
        "/auth/login",
        json={"email": "first@scopes.example.com", "password": "password123"},
    )
    assert resp.status_code == 200
    scopes = _decode_scope_claim(resp.json()["access_token"])
    # The first user becomes admin under the default config, which expands
    # to every cuopt permission codename. The literal "*" must never appear
    # in the token — spec 003 line 103 pins this.
    assert "cuopt.solve" in scopes
    assert "admin.users.manage" in scopes
    assert "*" not in scopes


@pytest.mark.asyncio
async def test_login_with_subset_scope_carries_only_that_subset(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    await _register(client, "narrow@scopes.example.com")
    resp = await client.post(
        "/auth/login",
        json={
            "email": "narrow@scopes.example.com",
            "password": "password123",
            "scope": "cuopt.view",
        },
    )
    assert resp.status_code == 200
    scopes = _decode_scope_claim(resp.json()["access_token"])
    assert scopes == ["cuopt.view"]


@pytest.mark.asyncio
async def test_login_with_unallowed_scope_returns_invalid_scope(client: AsyncClient, monkeypatch):
    """A user whose role doesn't grant ``never.exists`` cannot mint a token with it."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    monkeypatch.setattr(settings, "strict_scopes", False)
    await _register(client, "denied@scopes.example.com")
    resp = await client.post(
        "/auth/login",
        json={
            "email": "denied@scopes.example.com",
            "password": "password123",
            "scope": "never.exists",
        },
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"]["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_login_with_invalid_scope_pattern_rejected_at_validation(
    client: AsyncClient, monkeypatch
):
    """RFC 6749 §3.3 forbids ``"`` and ``\\`` inside scope entries — Pydantic
    rejects at validation time before the route runs."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    await _register(client, "bad-shape@scopes.example.com")
    resp = await client.post(
        "/auth/login",
        json={
            "email": "bad-shape@scopes.example.com",
            "password": "password123",
            # `"` is forbidden VSCHAR per RFC 6749 §3.3
            "scope": 'cuopt.solve has"quote',
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_invalid_scope_writes_audit_log(client: AsyncClient, db_session, monkeypatch):
    """Spec 003 §Testing: login-time invalid_scope writes an audit entry
    with ``AuditResult.failure`` so operators can spot integrators asking
    for scopes their role can't grant."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    monkeypatch.setattr(settings, "strict_scopes", False)
    await _register(client, "audit@scopes.example.com")
    resp = await client.post(
        "/auth/login",
        json={
            "email": "audit@scopes.example.com",
            "password": "password123",
            "scope": "never.exists",
        },
    )
    assert resp.status_code == 400

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "login_invalid_scope")
    )
    entries = list(result.scalars().all())
    assert len(entries) == 1
    entry = entries[0]
    assert entry.result == AuditResult.failure
    assert "never.exists" in (entry.target or "")
