"""Tests for `auth.decode_token` covering spec-001 acceptance criteria.

Each test exercises a rejection path the production token verifier MUST
catch — wrong issuer, post-grace rotated-out key, missing/unknown kid. If a
fix regresses, the matching test fails.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException

from accelerator_pack_auth_service import crypto
from accelerator_pack_auth_service.auth import create_access_token, decode_token
from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.crypto import (
    ROTATING_OUT_GRACE,
    get_active_signing_key,
    rotate_active_key,
)
from accelerator_pack_auth_service.models import Role, SigningKeyStatus, User


async def _make_user(db_session, email: str = "decode@test.com") -> User:
    user = User(
        email=email,
        name="Decode Test",
        password_hash="not-used-in-decode-tests",
        role=Role.user,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


def _sign_token(signing_key, payload: dict, *, include_kid: bool = True) -> str:
    headers = {"kid": signing_key.kid} if include_kid else {}
    return jwt.encode(
        payload,
        signing_key.private_pem,
        algorithm="RS256",
        headers=headers,
    )


def _payload(user: User, **overrides) -> dict:
    base = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "name": user.name,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iss": settings.issuer_url,
        "aud": [settings.pack],
        "exp": datetime.now(UTC) + timedelta(minutes=15),
        "iat": datetime.now(UTC),
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_decode_token_rejects_wrong_issuer(db_session):
    """T1 — token signed with a wrong `iss` claim is rejected."""
    user = await _make_user(db_session)
    signing_key = await get_active_signing_key(db_session)
    token = _sign_token(signing_key, _payload(user, iss="https://attacker.example.com"))

    with pytest.raises(HTTPException) as exc:
        await decode_token(db_session, token)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_decode_token_accepts_rotated_key_within_grace(db_session):
    """T2 — token issued before rotation still validates during the grace window."""
    user = await _make_user(db_session)
    token = await create_access_token(db_session, user)

    await rotate_active_key(db_session)

    payload = await decode_token(db_session, token)
    assert payload["sub"] == str(user.id)


@pytest.mark.asyncio
async def test_decode_token_rejects_rotated_key_past_grace(db_session):
    """T3 — token signed by a rotating_out key is rejected once the grace window has passed."""
    user = await _make_user(db_session)
    token = await create_access_token(db_session, user)
    original_kid = jwt.get_unverified_header(token)["kid"]

    await rotate_active_key(db_session)

    old_key = await crypto.get_key_by_kid(db_session, original_kid)
    assert old_key is not None
    assert old_key.status == SigningKeyStatus.rotating_out
    old_key.rotated_at = datetime.now(UTC) - ROTATING_OUT_GRACE - timedelta(minutes=1)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await decode_token(db_session, token)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_decode_token_rejects_missing_kid_header(db_session):
    """T4 — a token without a `kid` header is rejected."""
    user = await _make_user(db_session)
    signing_key = await get_active_signing_key(db_session)
    token = _sign_token(signing_key, _payload(user), include_kid=False)

    with pytest.raises(HTTPException) as exc:
        await decode_token(db_session, token)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Token missing kid header"


@pytest.mark.asyncio
async def test_decode_token_rejects_unknown_kid(db_session):
    """T5 — a token whose `kid` is not in signing_keys is rejected."""
    user = await _make_user(db_session)
    signing_key = await get_active_signing_key(db_session)
    payload = _payload(user)
    token = jwt.encode(
        payload,
        signing_key.private_pem,
        algorithm="RS256",
        headers={"kid": "kid-that-does-not-exist"},
    )

    with pytest.raises(HTTPException) as exc:
        await decode_token(db_session, token)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Unknown or revoked signing key"
