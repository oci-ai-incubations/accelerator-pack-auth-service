"""Tests for the ``require_scope`` FastAPI dependency factory.

The factory walks the bearer token's RFC 6749 §3.3 ``scope`` claim and 403s
when any required scope is missing. Drives the auth-service's own scope-
gated endpoints; the cuopt pack BE has a parallel factory with the same
shape (see cuopt-ev-routing-backend/tests/test_require_scope.py).
"""

import base64
import json

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient
from sqlalchemy import select

from accelerator_pack_auth_service.auth import require_scope
from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.models import AuditLog, AuditResult, User


def _decode_scope_claim(access_token: str) -> list[str]:
    payload_b64 = access_token.split(".")[1] + "=="
    raw = json.loads(base64.urlsafe_b64decode(payload_b64)).get("scope", "")
    return raw.split() if raw else []


async def _register_and_get_token(client: AsyncClient, email: str, scope: str | None) -> str:
    """Register a fresh user and mint an access token with the given scope request."""
    await client.post(
        "/auth/register",
        json={"email": email, "password": "password123", "name": email.split("@")[0]},
    )
    body: dict = {"email": email, "password": "password123"}
    if scope is not None:
        body["scope"] = scope
    resp = await client.post("/auth/login", json=body)
    assert resp.status_code == 200
    return resp.json()["access_token"]


async def _resolve_dep(dep, token: str, db_session) -> object:
    """Invoke the require_scope dep by manually resolving its FastAPI deps.

    The dep now chains through ``get_current_user``, so the test has to
    construct the credentials + user the same way FastAPI would.
    """
    from accelerator_pack_auth_service.auth import get_current_user

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    user = await get_current_user(creds, db_session)
    return await dep(user, creds, db_session)


@pytest.mark.asyncio
async def test_token_with_required_scope_passes(client: AsyncClient, db_session, monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    token = await _register_and_get_token(client, "has@scope.example.com", "cuopt.view")
    assert "cuopt.view" in _decode_scope_claim(token)

    dep = require_scope("cuopt.view")
    user = await _resolve_dep(dep, token, db_session)
    # Dep now returns the authenticated User after a successful scope check.
    assert user.email == "has@scope.example.com"


@pytest.mark.asyncio
async def test_token_missing_required_scope_403s(client: AsyncClient, db_session, monkeypatch):
    """A token that doesn't include the required scope must be rejected with
    the missing scope listed in the detail — the integrator can see exactly
    what's wrong."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    token = await _register_and_get_token(client, "missing@scope.example.com", "cuopt.view")

    dep = require_scope("cuopt.solve")
    with pytest.raises(HTTPException) as excinfo:
        await _resolve_dep(dep, token, db_session)
    assert excinfo.value.status_code == 403
    assert "cuopt.solve" in excinfo.value.detail


@pytest.mark.asyncio
async def test_token_multi_scope_required_lists_only_missing(
    client: AsyncClient, db_session, monkeypatch
):
    """When several scopes are required and only some are present, the 403
    detail lists *only* the missing ones — not the entire required set."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    token = await _register_and_get_token(
        client, "partial@scope.example.com", "cuopt.view cuopt.solve"
    )

    dep = require_scope("cuopt.view", "cuopt.solve", "admin.users.manage")
    with pytest.raises(HTTPException) as excinfo:
        await _resolve_dep(dep, token, db_session)
    assert excinfo.value.status_code == 403
    detail = excinfo.value.detail
    assert "admin.users.manage" in detail
    assert "cuopt.view" not in detail  # already on the token, not missing
    assert "cuopt.solve" not in detail


@pytest.mark.asyncio
async def test_deactivated_user_with_valid_token_fails_scope_check(
    client: AsyncClient, db_session, monkeypatch
):
    """A deactivated user whose token is still inside its expiry window must
    not pass a scope gate. Spec 003 review bug #4 — chaining through
    ``get_current_user`` enforces ``is_active`` before the scope check."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    token = await _register_and_get_token(client, "deactivated@scope.example.com", "cuopt.view")
    result = await db_session.execute(
        select(User).where(User.email == "deactivated@scope.example.com")
    )
    user = result.scalar_one()
    user.is_active = False
    await db_session.commit()

    dep = require_scope("cuopt.view")
    with pytest.raises(HTTPException) as excinfo:
        await _resolve_dep(dep, token, db_session)
    # get_current_user surfaces a 401 for inactive — not the scope-check 403.
    assert excinfo.value.status_code == 401


@pytest.mark.asyncio
async def test_scope_denial_writes_audit_log(client: AsyncClient, db_session, monkeypatch):
    """Spec 003 §Testing: insufficient-scope denials write an audit entry
    with ``AuditResult.failure`` and the missing scope listed."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    token = await _register_and_get_token(client, "audit@scope.example.com", "cuopt.view")

    dep = require_scope("cuopt.solve")
    with pytest.raises(HTTPException):
        await _resolve_dep(dep, token, db_session)

    result = await db_session.execute(select(AuditLog).where(AuditLog.action == "scope_denied"))
    entries = list(result.scalars().all())
    assert len(entries) == 1
    entry = entries[0]
    assert entry.result == AuditResult.failure
    assert "cuopt.solve" in (entry.target or "")
