"""Tests for GET /auth/scopes — pack scope vocabulary discovery."""

import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service.config import settings


async def _register_user(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "x@scopes.example.com", "password": "password123", "name": "X"},
    )
    assert resp.status_code == 201
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_scopes_endpoint_requires_authentication(client: AsyncClient):
    """No bearer token => 401. Anonymous discovery would let scanners profile
    the deployment surface even though the listed codenames aren't secret."""
    resp = await client.get("/auth/scopes")
    assert resp.status_code in {401, 403}


@pytest.mark.asyncio
async def test_scopes_endpoint_cuopt_returns_full_vocabulary(client: AsyncClient, monkeypatch):
    """The cuopt pack model declares nine permissions — every one shows up
    with a non-empty description."""
    monkeypatch.setattr(settings, "pack", "cuopt")
    token = await _register_user(client)
    resp = await client.get("/auth/scopes", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["pack_id"] == "cuopt"
    codenames = {s["codename"] for s in body["scopes"]}
    assert codenames == {
        "cuopt.solve",
        "cuopt.view",
        "chat.use",
        "weather.view",
        "config.read",
        "admin.users.manage",
        "admin.config.write",
        "admin.features.toggle",
        "admin.audit.view",
    }
    for entry in body["scopes"]:
        assert entry["description"], f"missing description for {entry['codename']}"


@pytest.mark.asyncio
async def test_scopes_endpoint_base_pack_returns_two_codenames(client: AsyncClient, monkeypatch):
    """The base pack declares only admin.users.manage + admin.audit.view."""
    monkeypatch.setattr(settings, "pack", "base")
    token = await _register_user(client)
    resp = await client.get("/auth/scopes", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["pack_id"] == "base"
    codenames = {s["codename"] for s in body["scopes"]}
    assert codenames == {"admin.users.manage", "admin.audit.view"}
