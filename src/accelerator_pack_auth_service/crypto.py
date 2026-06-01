"""RSA-2048 signing key lifecycle.

Tokens are signed with RS256; the active signing key lives in the
``signing_keys`` table and the public half is published via
``GET /.well-known/jwks.json``. Rotation marks the current active key as
``rotating_out`` (still served in the JWKS for the grace window so in-flight
tokens stay verifiable) and creates a new ``active`` key. Revocation removes
a key from the JWKS immediately and forces re-issue.

All helpers take an ``AsyncSession`` so they share the caller's transactional
context — the previous attempt at this spec opened its own ``async_session()``
and broke 57 tests because the fixture-overridden engine never saw the
``signing_keys`` table writes.
"""

import base64
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import SigningKey, SigningKeyStatus

logger = logging.getLogger(__name__)

ROTATING_OUT_GRACE = timedelta(hours=24)
_RSA_KEY_BITS = 2048
_RSA_PUBLIC_EXPONENT = 65537


def _generate_kid() -> str:
    now = datetime.now(UTC)
    return f"{now:%Y-%m-%d-%H%M%S}-{now.microsecond:06d}"


def _generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_KEY_BITS
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def _int_to_base64url(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


async def create_signing_key(db: AsyncSession) -> SigningKey:
    """Create a new active RSA signing key and persist it."""
    private_pem, public_pem = _generate_rsa_keypair()
    key = SigningKey(
        kid=_generate_kid(),
        algorithm="RS256",
        public_pem=public_pem,
        private_pem=private_pem,
        status=SigningKeyStatus.active,
        created_at=datetime.now(UTC),
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key


async def get_active_signing_key(db: AsyncSession) -> SigningKey:
    """Return the current active signing key, bootstrapping one if absent."""
    result = await db.execute(
        select(SigningKey)
        .where(SigningKey.status == SigningKeyStatus.active)
        .order_by(SigningKey.created_at.desc())
    )
    key = result.scalars().first()
    if key is not None:
        return key
    return await create_signing_key(db)


async def get_key_by_kid(db: AsyncSession, kid: str) -> SigningKey | None:
    """Return the signing key with the given kid, regardless of status."""
    result = await db.execute(select(SigningKey).where(SigningKey.kid == kid))
    return result.scalar_one_or_none()


async def list_keys_for_jwks(db: AsyncSession) -> list[SigningKey]:
    """Return keys that should appear in the public JWKS document.

    Includes ``active`` keys plus any ``rotating_out`` keys whose grace window
    has not expired. Revoked keys are never returned.
    """
    cutoff = datetime.now(UTC) - ROTATING_OUT_GRACE
    result = await db.execute(
        select(SigningKey)
        .where(SigningKey.status.in_([SigningKeyStatus.active, SigningKeyStatus.rotating_out]))
        .order_by(SigningKey.created_at.desc())
    )
    keys: list[SigningKey] = []
    for key in result.scalars().all():
        if key.status == SigningKeyStatus.rotating_out:
            rotated_at = key.rotated_at
            if rotated_at is None:
                logger.warning(
                    "signing key kid=%s is rotating_out but rotated_at is NULL; "
                    "excluding from JWKS (treated as outside grace window)",
                    key.kid,
                )
                continue
            if rotated_at.tzinfo is None:
                rotated_at = rotated_at.replace(tzinfo=UTC)
            if rotated_at < cutoff:
                continue
        keys.append(key)
    return keys


async def rotate_active_key(db: AsyncSession) -> SigningKey:
    """Mark the current active key as ``rotating_out`` and mint a new active key."""
    result = await db.execute(
        select(SigningKey).where(SigningKey.status == SigningKeyStatus.active)
    )
    now = datetime.now(UTC)
    for old in result.scalars().all():
        old.status = SigningKeyStatus.rotating_out
        old.rotated_at = now
    await db.commit()
    return await create_signing_key(db)


async def revoke_key(db: AsyncSession, kid: str) -> SigningKey | None:
    """Revoke the key with the given kid; tokens signed by it stop validating."""
    key = await get_key_by_kid(db, kid)
    if key is None:
        return None
    key.status = SigningKeyStatus.revoked
    key.revoked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(key)
    return key


def jwks_entry_for_key(key: SigningKey) -> dict[str, Any]:
    """Render a signing key as an RFC 7517 JWK entry (public half only)."""
    public_key = serialization.load_pem_public_key(key.public_pem.encode())
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": key.algorithm,
        "kid": key.kid,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }
