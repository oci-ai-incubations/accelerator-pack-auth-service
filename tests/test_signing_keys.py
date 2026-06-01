"""Unit tests for accelerator_pack_auth_service.crypto signing-key lifecycle."""

from datetime import UTC, datetime, timedelta

import pytest

from accelerator_pack_auth_service.crypto import (
    ROTATING_OUT_GRACE,
    create_signing_key,
    get_active_signing_key,
    get_key_by_kid,
    jwks_entry_for_key,
    list_keys_for_jwks,
    revoke_key,
    rotate_active_key,
)
from accelerator_pack_auth_service.models import SigningKeyStatus


@pytest.mark.asyncio
async def test_create_signing_key_persists_active_key(db_session):
    key = await create_signing_key(db_session)
    assert key.id is not None
    assert key.kid
    assert key.algorithm == "RS256"
    assert key.status == SigningKeyStatus.active
    assert "BEGIN PRIVATE KEY" in key.private_pem
    assert "BEGIN PUBLIC KEY" in key.public_pem


@pytest.mark.asyncio
async def test_get_active_signing_key_bootstraps_when_empty(db_session):
    key = await get_active_signing_key(db_session)
    assert key.status == SigningKeyStatus.active
    again = await get_active_signing_key(db_session)
    assert again.id == key.id


@pytest.mark.asyncio
async def test_get_key_by_kid_returns_none_for_unknown(db_session):
    assert await get_key_by_kid(db_session, "no-such-kid") is None


@pytest.mark.asyncio
async def test_rotate_active_key_marks_old_rotating_and_creates_new(db_session):
    first = await get_active_signing_key(db_session)
    rotated = await rotate_active_key(db_session)
    assert rotated.id != first.id
    assert rotated.status == SigningKeyStatus.active

    refreshed_first = await get_key_by_kid(db_session, first.kid)
    assert refreshed_first.status == SigningKeyStatus.rotating_out
    assert refreshed_first.rotated_at is not None


@pytest.mark.asyncio
async def test_list_keys_for_jwks_includes_active_and_recent_rotating(db_session):
    first = await get_active_signing_key(db_session)
    second = await rotate_active_key(db_session)
    keys = await list_keys_for_jwks(db_session)
    kids = {k.kid for k in keys}
    assert first.kid in kids
    assert second.kid in kids


@pytest.mark.asyncio
async def test_list_keys_for_jwks_excludes_revoked(db_session):
    first = await get_active_signing_key(db_session)
    revoked = await revoke_key(db_session, first.kid)
    assert revoked is not None
    assert revoked.status == SigningKeyStatus.revoked
    keys = await list_keys_for_jwks(db_session)
    assert all(k.kid != first.kid for k in keys)


@pytest.mark.asyncio
async def test_list_keys_for_jwks_drops_expired_rotating_out(db_session):
    first = await get_active_signing_key(db_session)
    await rotate_active_key(db_session)
    refreshed = await get_key_by_kid(db_session, first.kid)
    refreshed.rotated_at = datetime.now(UTC) - ROTATING_OUT_GRACE - timedelta(minutes=1)
    await db_session.commit()
    keys = await list_keys_for_jwks(db_session)
    assert all(k.kid != first.kid for k in keys)


@pytest.mark.asyncio
async def test_revoke_unknown_kid_returns_none(db_session):
    assert await revoke_key(db_session, "does-not-exist") is None


@pytest.mark.asyncio
async def test_jwks_entry_shape(db_session):
    key = await get_active_signing_key(db_session)
    entry = jwks_entry_for_key(key)
    assert entry["kty"] == "RSA"
    assert entry["use"] == "sig"
    assert entry["alg"] == "RS256"
    assert entry["kid"] == key.kid
    assert entry["n"]
    assert entry["e"]
