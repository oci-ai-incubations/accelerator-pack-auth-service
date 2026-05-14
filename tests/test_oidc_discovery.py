"""Tests for the OIDC discovery document."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_oidc_discovery_public(client: AsyncClient):
    resp = await client.get("/auth/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert "issuer" in body
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]
    assert body["jwks_uri"].endswith("/auth/.well-known/jwks.json")
    assert body["token_endpoint"].endswith("/auth/login")
    assert body["userinfo_endpoint"].endswith("/auth/me")


@pytest.mark.asyncio
async def test_oidc_discovery_respects_configured_issuer(client: AsyncClient, monkeypatch):
    from accelerator_pack_auth_service.config import settings

    monkeypatch.setattr(settings, "issuer_url", "https://pack.example.com/auth")
    resp = await client.get("/auth/.well-known/openid-configuration")
    body = resp.json()
    assert body["issuer"] == "https://pack.example.com/auth"
    assert body["jwks_uri"] == "https://pack.example.com/auth/.well-known/jwks.json"
    assert body["token_endpoint"] == "https://pack.example.com/auth/login"
