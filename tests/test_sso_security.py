"""End-to-end SSO security tests.

Covers the IdP-side surface ``exchange_oidc_code`` + ``sso_token_exchange``:

- Successful token exchange JIT-provisions the user and mints internal tokens.
- ID-token signature, ``iss``, ``aud``, ``exp``, and ``nonce`` are all
  cryptographically verified.
- The single-use ``state`` from /authorize is required and must be unexpired.

Uses ``respx`` to stub the IdP's discovery, token, userinfo, and JWKS
endpoints. The IdP-side keypair is minted per test so each scenario controls
its own signing-key trust boundary.
"""

import time
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from httpx import AsyncClient

from accelerator_pack_auth_service import sso_service

IDP_ISSUER = "https://idp.test.example.com"
IDP_CLIENT_ID = "auth-service-client"
IDP_CLIENT_SECRET = "client-secret"  # noqa: S105 — test fixture
IDP_DISCOVERY_URL = f"{IDP_ISSUER}/.well-known/openid-configuration"
IDP_TOKEN_URL = f"{IDP_ISSUER}/oauth/token"
IDP_USERINFO_URL = f"{IDP_ISSUER}/userinfo"
IDP_JWKS_URL = f"{IDP_ISSUER}/jwks"


def _jwk_from_public_key(public_key: RSAPublicKey, kid: str) -> dict:
    """Encode an RSA public key as an RFC 7517 JWK."""
    numbers = public_key.public_numbers()

    def _b64url(n: int) -> str:
        import base64

        byte_length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(numbers.n),
        "e": _b64url(numbers.e),
    }


def _mint_idp_keypair(kid: str = "idp-test-kid"):
    """Mint an in-memory RSA keypair for the mock IdP, plus its JWK form."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_jwk = _jwk_from_public_key(private_key.public_key(), kid)
    return private_pem, public_jwk, kid


def _make_id_token(
    private_pem: bytes,
    kid: str,
    *,
    issuer: str = IDP_ISSUER,
    audience: str = IDP_CLIENT_ID,
    subject: str = "user-from-idp",
    email: str = "sso-e2e@example.com",
    name: str = "SSO E2E",
    nonce: str | None = None,
    exp_offset: int = 600,
    iat_offset: int = 0,
    extra_claims: dict | None = None,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": now + exp_offset,
        "iat": now + iat_offset,
        "email": email,
        "name": name,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


def _discovery_doc() -> dict:
    return {
        "issuer": IDP_ISSUER,
        "token_endpoint": IDP_TOKEN_URL,
        "userinfo_endpoint": IDP_USERINFO_URL,
        "jwks_uri": IDP_JWKS_URL,
        "authorization_endpoint": f"{IDP_ISSUER}/authorize",
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def _reset_sso_caches() -> None:
    """Wipe in-process discovery and JWKS caches between tests."""
    sso_service._discovery_cache.clear()
    sso_service._jwks_cache.clear()


async def _register_admin(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={
            "email": "admin@sso-security.example.com",
            "password": "password123",
            "name": "Admin",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


async def _create_provider(client: AsyncClient, admin_token: str, slug: str = "idp-test") -> int:
    resp = await client.post(
        "/auth/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "type": "oidc",
            "name": "Test IdP",
            "slug": slug,
            "config": {
                "issuer": IDP_ISSUER,
                "client_id": IDP_CLIENT_ID,
                "client_secret": IDP_CLIENT_SECRET,
                "token_url": IDP_TOKEN_URL,
                "userinfo_url": IDP_USERINFO_URL,
                "jwks_url": IDP_JWKS_URL,
                "authorize_url": f"{IDP_ISSUER}/authorize",
            },
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _authorize(client: AsyncClient, slug: str) -> str:
    resp = await client.get(
        f"/auth/sso/{slug}/authorize",
        params={"redirect_uri": "http://localhost:3000/cb"},
    )
    assert resp.status_code == 200
    return resp.json()["state"]


def _mock_idp(
    respx_mock: respx.MockRouter,
    *,
    public_jwk: dict,
    id_token: str,
    userinfo: dict | None = None,
    token_status: int = 200,
) -> None:
    respx_mock.get(IDP_DISCOVERY_URL).mock(return_value=httpx.Response(200, json=_discovery_doc()))
    respx_mock.get(IDP_JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [public_jwk]}))
    token_body = {"id_token": id_token, "access_token": "idp-access-token", "token_type": "Bearer"}
    respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(token_status, json=token_body if token_status == 200 else {})
    )
    respx_mock.get(IDP_USERINFO_URL).mock(
        return_value=httpx.Response(
            200, json=userinfo if userinfo is not None else {"sub": "user-from-idp"}
        )
    )


# ── Happy path ────────────────────────────────────


@pytest.mark.asyncio
async def test_token_exchange_happy_path_signed_id_token(
    client: AsyncClient, db_session, respx_mock
):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="happy-idp")

    private_pem, public_jwk, kid = _mint_idp_keypair()
    # Mint state via the authorize endpoint, then read the nonce out of the
    # persisted row so the synthetic ID token can carry the right value.
    state = await _authorize(client, "happy-idp")
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()
    nonce = row.nonce

    id_token = _make_id_token(private_pem, kid, nonce=nonce)
    _mock_idp(
        respx_mock,
        public_jwk=public_jwk,
        id_token=id_token,
        userinfo={
            "sub": "user-from-idp",
            "email": "sso-e2e@example.com",
            "name": "SSO E2E",
        },
    )

    resp = await client.post(
        "/auth/sso/happy-idp/token",
        json={"code": "auth-code", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["email"] == "sso-e2e@example.com"
    assert body["access_token"]


# ── ID-token verification failures ────────────────


@pytest.mark.asyncio
async def test_token_exchange_id_token_signed_by_attacker_rejected(
    client: AsyncClient, db_session, respx_mock
):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="bad-sig-idp")

    # The IdP publishes its real public key in JWKS, but the ID token is
    # signed by a different (attacker-controlled) key.
    _real_priv, real_jwk, real_kid = _mint_idp_keypair(kid="real-kid")
    attacker_priv, _attacker_jwk, _ = _mint_idp_keypair(kid="real-kid")

    state = await _authorize(client, "bad-sig-idp")
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()
    forged_token = _make_id_token(attacker_priv, real_kid, nonce=row.nonce)
    _mock_idp(respx_mock, public_jwk=real_jwk, id_token=forged_token)

    resp = await client.post(
        "/auth/sso/bad-sig-idp/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 401
    assert "Invalid ID token" in resp.text


@pytest.mark.asyncio
async def test_token_exchange_id_token_wrong_issuer_rejected(
    client: AsyncClient, db_session, respx_mock
):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="wrong-iss-idp")
    private_pem, public_jwk, kid = _mint_idp_keypair()

    state = await _authorize(client, "wrong-iss-idp")
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()

    id_token = _make_id_token(
        private_pem,
        kid,
        issuer="https://attacker.example.com",
        nonce=row.nonce,
    )
    _mock_idp(respx_mock, public_jwk=public_jwk, id_token=id_token)

    resp = await client.post(
        "/auth/sso/wrong-iss-idp/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_token_exchange_id_token_wrong_audience_rejected(
    client: AsyncClient, db_session, respx_mock
):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="wrong-aud-idp")
    private_pem, public_jwk, kid = _mint_idp_keypair()

    state = await _authorize(client, "wrong-aud-idp")
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()

    id_token = _make_id_token(
        private_pem,
        kid,
        audience="some-other-client",
        nonce=row.nonce,
    )
    _mock_idp(respx_mock, public_jwk=public_jwk, id_token=id_token)

    resp = await client.post(
        "/auth/sso/wrong-aud-idp/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_token_exchange_expired_id_token_rejected(
    client: AsyncClient, db_session, respx_mock
):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="expired-idp")
    private_pem, public_jwk, kid = _mint_idp_keypair()

    state = await _authorize(client, "expired-idp")
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()

    # exp 10 minutes in the past, well outside the 60s leeway.
    id_token = _make_id_token(private_pem, kid, exp_offset=-600, nonce=row.nonce)
    _mock_idp(respx_mock, public_jwk=public_jwk, id_token=id_token)

    resp = await client.post(
        "/auth/sso/expired-idp/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_token_exchange_nonce_mismatch_rejected(client: AsyncClient, db_session, respx_mock):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="bad-nonce-idp")
    private_pem, public_jwk, kid = _mint_idp_keypair()

    state = await _authorize(client, "bad-nonce-idp")
    # ID token carries a nonce we didn't mint — replay defense fires.
    id_token = _make_id_token(private_pem, kid, nonce="wrong-nonce")
    _mock_idp(respx_mock, public_jwk=public_jwk, id_token=id_token)

    resp = await client.post(
        "/auth/sso/bad-nonce-idp/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 401
    assert "nonce" in resp.text.lower()


# ── State validation ──────────────────────────────


@pytest.mark.asyncio
async def test_token_exchange_unknown_state_rejected(client: AsyncClient):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="state-test")

    resp = await client.post(
        "/auth/sso/state-test/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": "made-up"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"]["error"] == "invalid_state"


@pytest.mark.asyncio
async def test_token_exchange_missing_state_rejected(client: AsyncClient):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="missing-state")

    resp = await client.post(
        "/auth/sso/missing-state/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"]["error"] == "invalid_state"


@pytest.mark.asyncio
async def test_token_exchange_expired_state_rejected(client: AsyncClient, db_session):
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="exp-state")

    state = await _authorize(client, "exp-state")
    # Backdate the row so consume_sso_state sees it as expired.
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    resp = await client.post(
        "/auth/sso/exp-state/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"]["error"] == "invalid_state"


@pytest.mark.asyncio
async def test_token_exchange_state_is_single_use(client: AsyncClient, db_session, respx_mock):
    """A state value rejected on second use even if the first attempt succeeds."""
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="single-use")
    private_pem, public_jwk, kid = _mint_idp_keypair()

    state = await _authorize(client, "single-use")
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()
    id_token = _make_id_token(private_pem, kid, nonce=row.nonce)
    _mock_idp(respx_mock, public_jwk=public_jwk, id_token=id_token)

    resp1 = await client.post(
        "/auth/sso/single-use/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp1.status_code == 200

    resp2 = await client.post(
        "/auth/sso/single-use/token",
        json={"code": "c", "redirect_uri": "http://localhost:3000/cb", "state": state},
    )
    assert resp2.status_code == 400
    assert resp2.json()["detail"]["error"] == "invalid_state"


# ── External-ID preference (D4) ───────────────────


@pytest.mark.asyncio
async def test_select_external_id_prefers_oid_then_user_id_then_sub():
    from accelerator_pack_auth_service.sso_service import select_external_id

    assert select_external_id({"sub": "s", "user_id": "u", "oid": "o"}) == "o"
    assert select_external_id({"sub": "s", "user_id": "u"}) == "u"
    assert select_external_id({"sub": "s"}) == "s"
    assert select_external_id({}) == ""


# ── Authenticated JWKS fallback (IDCS-style admin-gated JWKS) ─────


def _reset_jwks_caches() -> None:
    sso_service._jwks_cache.clear()
    sso_service._cc_token_cache.clear()


@pytest.mark.asyncio
async def test_fetch_jwks_401_without_fallback_raises(respx_mock):
    """Standard OIDC: a 401 on the JWKS endpoint is a hard failure."""
    from fastapi import HTTPException

    _reset_jwks_caches()
    respx_mock.get(IDP_JWKS_URL).mock(return_value=httpx.Response(401))

    with pytest.raises(HTTPException) as exc_info:
        await sso_service._fetch_jwks(IDP_JWKS_URL)
    assert exc_info.value.status_code == 401
    assert "JWKS fetch failed (401)" in exc_info.value.detail


@pytest.mark.asyncio
async def test_fetch_jwks_401_with_fallback_retries_authenticated(respx_mock):
    """IDCS-style admin-gated JWKS: 401 triggers a client_credentials retry."""
    _reset_jwks_caches()
    _, public_jwk, _ = _mint_idp_keypair(kid="gated-kid")

    respx_mock.get(IDP_JWKS_URL).mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json={"keys": [public_jwk]}),
        ]
    )
    token_route = respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "cc-bearer",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
    )

    jwks = await sso_service._fetch_jwks(
        IDP_JWKS_URL,
        oauth_fallback=(
            IDP_TOKEN_URL,
            IDP_CLIENT_ID,
            IDP_CLIENT_SECRET,
            "urn:opc:idm:__myscopes__",
        ),
    )
    assert jwks["gated-kid"] is not None
    assert token_route.call_count == 1


@pytest.mark.asyncio
async def test_fetch_jwks_fallback_cc_failure_surfaces_cc_error(respx_mock):
    """When the fallback CC grant itself fails, the error names the CC step."""
    from fastapi import HTTPException

    _reset_jwks_caches()
    respx_mock.get(IDP_JWKS_URL).mock(return_value=httpx.Response(401))
    respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(
            401, json={"error": "unauthorized_client", "error_description": "no grant"}
        )
    )

    with pytest.raises(HTTPException) as exc_info:
        await sso_service._fetch_jwks(
            IDP_JWKS_URL,
            oauth_fallback=(IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, None),
        )
    assert exc_info.value.status_code == 401
    assert "Client-credentials token fetch failed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_client_credentials_token_is_cached_across_calls(respx_mock):
    """Second call within TTL hits the cache rather than re-POSTing."""
    _reset_jwks_caches()
    token_route = respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "cached-bearer", "expires_in": 3600},
        )
    )

    first = await sso_service._client_credentials_token(
        IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, "openid"
    )
    second = await sso_service._client_credentials_token(
        IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, "openid"
    )
    assert first == second == "cached-bearer"
    assert token_route.call_count == 1


@pytest.mark.asyncio
async def test_client_credentials_token_missing_access_token_raises(respx_mock):
    from fastapi import HTTPException

    _reset_jwks_caches()
    respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"token_type": "Bearer"})
    )

    with pytest.raises(HTTPException) as exc_info:
        await sso_service._client_credentials_token(
            IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, None
        )
    assert "missing access_token" in exc_info.value.detail


# ── Hardening wave regressions ───────────────────


@pytest.mark.asyncio
async def test_fetch_jwks_error_does_not_leak_url(respx_mock):
    """The JWKS fetch error detail must not echo the (possibly admin-gated)
    internal URL back to the caller — the URL is logged server-side only."""
    from fastapi import HTTPException

    _reset_jwks_caches()
    respx_mock.get(IDP_JWKS_URL).mock(return_value=httpx.Response(500))

    with pytest.raises(HTTPException) as exc_info:
        await sso_service._fetch_jwks(IDP_JWKS_URL)
    assert exc_info.value.status_code == 401
    assert IDP_JWKS_URL not in exc_info.value.detail


@pytest.mark.asyncio
async def test_cc_token_error_does_not_leak_idp_response(respx_mock):
    """CC-token error detail must not echo the IdP's response body."""
    from fastapi import HTTPException

    _reset_jwks_caches()
    respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(
            401,
            json={"error": "unauthorized_client", "internal_request_id": "leak-me-x9z"},
        )
    )

    with pytest.raises(HTTPException) as exc_info:
        await sso_service._client_credentials_token(
            IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, None
        )
    assert "leak-me-x9z" not in exc_info.value.detail
    assert "unauthorized_client" not in exc_info.value.detail


@pytest.mark.asyncio
async def test_cc_token_cache_key_includes_secret_hash(respx_mock):
    """Rotating the client_secret must force a fresh CC token fetch even when
    the same (token_url, client_id) pair is reused."""
    _reset_jwks_caches()
    token_route = respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    )

    await sso_service._client_credentials_token(IDP_TOKEN_URL, IDP_CLIENT_ID, "old-secret", None)
    await sso_service._client_credentials_token(IDP_TOKEN_URL, IDP_CLIENT_ID, "new-secret", None)

    assert token_route.call_count == 2


@pytest.mark.asyncio
async def test_cc_token_ttl_floor_skips_cache_when_lifetime_under_margin(respx_mock):
    """If the IdP says the token lives for less than the refresh margin, the
    cache must not hold it (otherwise we'd return a stale/expired token on
    the next call)."""
    _reset_jwks_caches()
    token_route = respx_mock.post(IDP_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "short-lived", "expires_in": 10},
        )
    )

    first = await sso_service._client_credentials_token(
        IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, None
    )
    second = await sso_service._client_credentials_token(
        IDP_TOKEN_URL, IDP_CLIENT_ID, IDP_CLIENT_SECRET, None
    )

    assert first == second == "short-lived"
    assert token_route.call_count == 2  # not cached — fetched twice


@pytest.mark.asyncio
async def test_resolve_oidc_endpoints_rejects_http_scheme():
    """Operator-supplied or discovery-supplied non-HTTPS endpoint URLs must
    be rejected so a spoofed discovery doc can't direct fetches at
    http://169.254.169.254/... (cloud instance metadata) or internal HTTP
    services."""
    from fastapi import HTTPException

    discovery = {
        "issuer": "https://idp.test",
        "token_endpoint": "http://idp.test/oauth/token",  # http:// — rejected
        "userinfo_endpoint": "https://idp.test/userinfo",
        "jwks_uri": "https://idp.test/jwks",
        "authorization_endpoint": "https://idp.test/authorize",
    }

    with pytest.raises(HTTPException) as exc_info:
        sso_service._resolve_oidc_endpoints({"issuer": "https://idp.test"}, discovery)
    assert exc_info.value.status_code == 422
    assert "https://" in exc_info.value.detail or "must use https" in exc_info.value.detail


@pytest.mark.asyncio
async def test_resolve_oidc_endpoints_rejects_file_scheme_in_config():
    """Operator-pinned endpoint URLs go through the same scheme allowlist."""
    from fastapi import HTTPException

    config = {
        "issuer": "https://idp.test",
        "jwks_url": "file:///etc/passwd",  # file:// — rejected
    }
    discovery = {
        "issuer": "https://idp.test",
        "token_endpoint": "https://idp.test/token",
        "authorization_endpoint": "https://idp.test/authorize",
        "jwks_uri": "https://idp.test/jwks",
        "userinfo_endpoint": "https://idp.test/userinfo",
    }

    with pytest.raises(HTTPException):
        sso_service._resolve_oidc_endpoints(config, discovery)


@pytest.mark.asyncio
async def test_authorize_rejects_redirect_uri_outside_allowlist(client: AsyncClient):
    """When AUTH_SSO_REDIRECT_BASE_URL is set, /authorize must reject a
    redirect_uri that doesn't match {base}/sso/callback/{slug}."""
    from unittest.mock import patch

    from accelerator_pack_auth_service.config import settings

    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="allowlist-test")

    with patch.object(settings, "sso_redirect_base_url", "https://pack.example.com"):
        # Wrong host
        resp = await client.get(
            "/auth/sso/allowlist-test/authorize",
            params={"redirect_uri": "https://attacker.example.com/sso/callback/allowlist-test"},
        )
        assert resp.status_code == 400
        # Wrong slug
        resp = await client.get(
            "/auth/sso/allowlist-test/authorize",
            params={"redirect_uri": "https://pack.example.com/sso/callback/other-slug"},
        )
        assert resp.status_code == 400
        # Exact match passes
        resp = await client.get(
            "/auth/sso/allowlist-test/authorize",
            params={"redirect_uri": "https://pack.example.com/sso/callback/allowlist-test"},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_exchange_rejects_redirect_uri_mismatch(
    client: AsyncClient, db_session, respx_mock
):
    """/token must reject when the presented redirect_uri doesn't match the
    one stored against the state row at /authorize time."""
    _reset_sso_caches()
    admin_token = await _register_admin(client)
    await _create_provider(client, admin_token, slug="redir-mismatch")

    state = await _authorize(client, "redir-mismatch")
    private_pem, public_jwk, kid = _mint_idp_keypair()
    from sqlalchemy import select

    from accelerator_pack_auth_service.models import SsoState

    row = (await db_session.execute(select(SsoState).where(SsoState.state == state))).scalar_one()
    id_token = _make_id_token(private_pem, kid, nonce=row.nonce)
    _mock_idp(respx_mock, public_jwk=public_jwk, id_token=id_token)

    resp = await client.post(
        "/auth/sso/redir-mismatch/token",
        json={
            "code": "c",
            "redirect_uri": "http://localhost:3000/different-cb",
            "state": state,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_state"
