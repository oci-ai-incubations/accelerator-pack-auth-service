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
