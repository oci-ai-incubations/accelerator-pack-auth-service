"""Tests for the OIDC discovery and RFC 8414 AS-metadata documents."""

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
    # token_endpoint advertises the RFC 6749 endpoint (client_credentials),
    # not the password-grant convenience route at /auth/login.
    assert body["token_endpoint"].endswith("/auth/oauth/token")
    assert body["userinfo_endpoint"].endswith("/auth/me")
    # Auth-service has no authorization_endpoint of its own — we're a token
    # issuer, not an auth-code OP — so the field is intentionally omitted.
    assert "authorization_endpoint" not in body
    assert "response_types_supported" not in body
    # RFC 8414 grant_types_supported pins the surface we actually accept.
    assert "client_credentials" in body["grant_types_supported"]
    assert "password" in body["grant_types_supported"]


@pytest.mark.asyncio
async def test_oidc_discovery_respects_configured_issuer(client: AsyncClient, monkeypatch):
    from accelerator_pack_auth_service.config import settings

    monkeypatch.setattr(settings, "issuer_url", "https://pack.example.com/auth")
    resp = await client.get("/auth/.well-known/openid-configuration")
    body = resp.json()
    assert body["issuer"] == "https://pack.example.com/auth"
    assert body["jwks_uri"] == "https://pack.example.com/auth/.well-known/jwks.json"
    assert body["token_endpoint"] == "https://pack.example.com/auth/oauth/token"


@pytest.mark.asyncio
async def test_as_metadata_alias_matches_openid_config(client: AsyncClient):
    """The RFC 8414 endpoint and the OIDC alias return the same body."""
    rfc8414 = await client.get("/auth/.well-known/oauth-authorization-server")
    oidc = await client.get("/auth/.well-known/openid-configuration")
    assert rfc8414.status_code == 200
    assert oidc.status_code == 200
    assert rfc8414.json() == oidc.json()
