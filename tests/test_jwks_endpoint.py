"""Tests for the public /.well-known/jwks.json endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_jwks_endpoint_public_returns_active_key(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "jwks@test.com", "password": "password123", "name": "JWKS"},
    )
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert "keys" in body
    assert len(body["keys"]) >= 1
    first = body["keys"][0]
    assert first["kty"] == "RSA"
    assert first["alg"] == "RS256"
    assert first["use"] == "sig"
    assert first["kid"]
    assert first["n"]
    assert first["e"]


@pytest.mark.asyncio
async def test_jwks_endpoint_sets_cache_control(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "cache@test.com", "password": "password123", "name": "Cache"},
    )
    resp = await client.get("/.well-known/jwks.json")
    assert resp.headers["cache-control"] == "public, max-age=3600"


@pytest.mark.asyncio
async def test_jwks_endpoint_does_not_require_auth(client: AsyncClient):
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_issued_token_kid_present_in_jwks(client: AsyncClient):
    import jwt

    reg = await client.post(
        "/auth/register",
        json={"email": "kid@test.com", "password": "password123", "name": "Kid"},
    )
    token = reg.json()["access_token"]
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"]

    jwks = (await client.get("/.well-known/jwks.json")).json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert header["kid"] in kids
