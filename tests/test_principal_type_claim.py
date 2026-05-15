"""User + client tokens both carry ``principal_type``; decode_token returns it."""

import jwt
import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service import auth, clients
from accelerator_pack_auth_service.models import Role, User


async def _register_first_admin(client: AsyncClient) -> dict:
    resp = await client.post(
        "/auth/register",
        json={"email": "first@principal.example.com", "password": "password123", "name": "First"},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_user_access_token_carries_principal_type_user(client: AsyncClient):
    payload = await _register_first_admin(client)
    claims = jwt.decode(payload["access_token"], options={"verify_signature": False})
    assert claims["principal_type"] == "user"


@pytest.mark.asyncio
async def test_decode_token_accepts_user_token_with_principal_type(client: AsyncClient, db_session):
    payload = await _register_first_admin(client)
    decoded = await auth.decode_token(db_session, payload["access_token"])
    assert decoded["principal_type"] == "user"
    assert decoded["sub"] == "1"


@pytest.mark.asyncio
async def test_user_access_token_carries_rfc9068_typ_header(client: AsyncClient):
    """RFC 9068 §2.1 — access tokens MUST carry ``typ: at+jwt`` in the header."""
    payload = await _register_first_admin(client)
    header = jwt.get_unverified_header(payload["access_token"])
    assert header["typ"] == "at+jwt"


@pytest.mark.asyncio
async def test_user_access_token_carries_client_id_claim(client: AsyncClient):
    """RFC 9068 §2.2 — access tokens carry a ``client_id`` claim. User-grant
    tokens emit the sentinel ``user-login`` so the claim shape is uniform
    across user and client paths."""
    payload = await _register_first_admin(client)
    claims = jwt.decode(payload["access_token"], options={"verify_signature": False})
    assert claims["client_id"] == "user-login"


@pytest.mark.asyncio
async def test_create_client_access_token_carries_principal_type_client(db_session):
    """Direct unit test of ``create_client_access_token`` — no HTTP round trip."""
    from datetime import UTC, datetime

    owner = User(
        email="o@principal.example.com",
        name="O",
        password_hash="x",
        role=Role.admin,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    db_session.add(owner)
    await db_session.commit()
    await db_session.refresh(owner)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=["cuopt.view"],
        expires_at=None,
    )
    token = await auth.create_client_access_token(db_session, account, ["cuopt.view"])
    decoded = await auth.decode_token(db_session, token)
    assert decoded["principal_type"] == "client"
    assert decoded["sub"] == f"client:{account.client_id}"
    assert decoded["client_id"] == account.client_id
    assert decoded["scope"] == "cuopt.view"
    # RFC 9068 §2.1 — client tokens MUST also carry typ: at+jwt
    header = jwt.get_unverified_header(token)
    assert header["typ"] == "at+jwt"
