"""Service-account (OAuth2 client) lifecycle and credential helpers.

Service accounts are the OAuth2 client_credentials grant's principal — a
non-human identity created by an admin, authenticated by a bcrypt-hashed
shared secret. The plaintext secret is shown exactly once at creation (and
at every rotation) and is never persisted.

Functions take ``db: AsyncSession`` and mutate through it. The caller owns
the session — opening a fresh ``async_session()`` here would bypass the
FastAPI test override and read a different engine.
"""

import secrets
from datetime import UTC, datetime
from typing import Any, Final

import bcrypt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import ServiceAccount
from .scopes import deserialize_scopes, serialize_scopes

# Prefixes per OWASP API Security recommendations: make credentials
# self-identifying so leak scanners can pattern-match them on disclosure.
CLIENT_ID_PREFIX = "cli_"
CLIENT_SECRET_PREFIX = "csk_"  # noqa: S105 — public prefix string, not a credential
# ~16 bytes (22 chars url-safe-base64) for client_id, ~32 bytes (43 chars)
# for client_secret. token_urlsafe(n) emits ceil(n*4/3) chars.
_CLIENT_ID_BYTES = 16
_CLIENT_SECRET_BYTES = 32


class _Unset:
    """Sentinel type for ``update_client`` arguments that mean 'leave unchanged'.

    Distinguishes "field omitted from the patch" from "field explicitly set to
    None" so admins can clear ``description`` and ``expires_at`` by passing
    ``None`` rather than being forced to keep the old value.
    """

    _singleton: "_Unset | None" = None

    def __new__(cls) -> "_Unset":
        if cls._singleton is None:
            cls._singleton = super().__new__(cls)
        return cls._singleton

    def __repr__(self) -> str:
        return "_UNSET"


_UNSET: Final[_Unset] = _Unset()


# Module-level dummy bcrypt hash for the unknown-client branch on the token
# endpoint. We still pay the bcrypt cost when ``get_client_by_client_id``
# returns None so an attacker can't time-correlate the response to learn
# which client_ids exist. Generated lazily on first use to avoid hashing at
# import time (which would slow test collection).
_DUMMY_BCRYPT_HASH: str | None = None


def get_dummy_bcrypt_hash() -> str:
    """Return a constant bcrypt hash; compute once, reuse for timing parity."""
    global _DUMMY_BCRYPT_HASH
    if _DUMMY_BCRYPT_HASH is None:
        _DUMMY_BCRYPT_HASH = bcrypt.hashpw(
            b"unknown-client-timing-parity",
            bcrypt.gensalt(rounds=settings.bcrypt_rounds),
        ).decode()
    return _DUMMY_BCRYPT_HASH


def generate_client_id() -> str:
    """Generate a public-safe client_id (``cli_`` + 22 url-safe-base64 chars)."""
    return CLIENT_ID_PREFIX + secrets.token_urlsafe(_CLIENT_ID_BYTES)


def generate_client_secret() -> str:
    """Generate a high-entropy client_secret (``csk_`` + 43 url-safe-base64 chars)."""
    return CLIENT_SECRET_PREFIX + secrets.token_urlsafe(_CLIENT_SECRET_BYTES)


def hash_secret(plain: str) -> str:
    """Bcrypt-hash a client_secret using the configured rounds."""
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def verify_secret(plain: str, hashed: str) -> bool:
    """Constant-time compare a presented client_secret against its bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        # Malformed hash on disk (truncation, encoding corruption). Treat as
        # mismatch; never raise — the token endpoint maps every failure to the
        # same invalid_client response to avoid enumeration.
        return False


async def create_client(
    db: AsyncSession,
    *,
    owner_id: int,
    name: str,
    description: str | None,
    scopes: list[str],
    expires_at: datetime | None,
) -> tuple[ServiceAccount, str]:
    """Mint a new service account and persist its bcrypt-hashed secret.

    Returns ``(account, plaintext_secret)``. The plaintext is shown once in
    the API response and never persisted — callers must hand it back to the
    admin immediately and discard it.
    """
    client_id = generate_client_id()
    plaintext_secret = generate_client_secret()
    account = ServiceAccount(
        client_id=client_id,
        client_secret_hash=hash_secret(plaintext_secret),
        name=name,
        description=description,
        scopes=serialize_scopes(scopes),
        owner_user_id=owner_id,
        is_active=True,
        expires_at=expires_at,
        created_at=datetime.now(UTC),
    )
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account, plaintext_secret


async def seed_bootstrap_client(
    db: AsyncSession,
    *,
    client_id: str,
    client_secret: str,
    scopes: list[str],
) -> ServiceAccount:
    """Idempotently upsert an env-seeded (ownerless) service account on startup.

    Unlike ``create_client`` (admin API), the id + secret are supplied by the
    deployment (env), there is no human owner, and the operation is safe to run
    on every boot:
      - if the client_id does not exist, insert it (bcrypt-hashing the secret);
      - if it exists, re-hash the secret + refresh scopes so a rotated env
        secret takes effect, and re-activate it if it had been revoked.
    """
    account = await get_client_by_client_id(db, client_id)
    if account is None:
        account = ServiceAccount(
            client_id=client_id,
            client_secret_hash=hash_secret(client_secret),
            name="bootstrap-service-account",
            description="Env-seeded machine identity (AUTH_BOOTSTRAP_CLIENT_*).",
            scopes=serialize_scopes(scopes),
            owner_user_id=None,
            is_active=True,
            created_at=datetime.now(UTC),
        )
        db.add(account)
    else:
        account.client_secret_hash = hash_secret(client_secret)
        account.scopes = serialize_scopes(scopes)
        account.is_active = True
        account.revoked_at = None
    await db.commit()
    await db.refresh(account)
    return account


async def get_client_by_client_id(db: AsyncSession, client_id: str) -> ServiceAccount | None:
    """Look up a service account by its public client_id."""
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.client_id == client_id))
    return result.scalar_one_or_none()


async def get_client_by_id(db: AsyncSession, account_id: int) -> ServiceAccount | None:
    """Look up a service account by its primary-key id."""
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.id == account_id))
    return result.scalar_one_or_none()


async def rotate_secret(db: AsyncSession, account_id: int) -> tuple[ServiceAccount, str] | None:
    """Mint a new secret for an existing client and persist its bcrypt hash.

    Returns ``(account, plaintext)`` on success or ``None`` when the account
    doesn't exist. The previous secret stops working immediately — callers
    must update consumers before the call to avoid a service blip.
    """
    account = await get_client_by_id(db, account_id)
    if account is None:
        return None
    new_plain = generate_client_secret()
    account.client_secret_hash = hash_secret(new_plain)
    await db.commit()
    await db.refresh(account)
    return account, new_plain


async def revoke_client(db: AsyncSession, account_id: int) -> ServiceAccount | None:
    """Soft-delete a service account: deactivate + stamp ``revoked_at``."""
    account = await get_client_by_id(db, account_id)
    if account is None:
        return None
    account.is_active = False
    account.revoked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(account)
    return account


async def update_client(
    db: AsyncSession,
    account_id: int,
    *,
    name: str | None = None,
    description: str | None | _Unset = _UNSET,
    scopes: list[str] | None = None,
    expires_at: datetime | None | _Unset = _UNSET,
    is_active: bool | None = None,
) -> ServiceAccount | None:
    """Patch mutable fields on a service account.

    ``description`` and ``expires_at`` use the ``_UNSET`` sentinel to
    distinguish "field omitted from the patch" (leave unchanged) from
    "explicit None" (clear the column). Without this, an admin couldn't
    clear an existing description or expiry once set.
    """
    account = await get_client_by_id(db, account_id)
    if account is None:
        return None
    if name is not None:
        account.name = name
    if not isinstance(description, _Unset):
        account.description = description
    if scopes is not None:
        account.scopes = serialize_scopes(scopes)
    if not isinstance(expires_at, _Unset):
        account.expires_at = expires_at
    if is_active is not None:
        account.is_active = is_active
        if is_active is False and account.revoked_at is None:
            account.revoked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(account)
    return account


async def list_clients_for_owner(db: AsyncSession, owner_id: int) -> list[ServiceAccount]:
    """List every service account owned by the given user, newest first."""
    result = await db.execute(
        select(ServiceAccount)
        .where(ServiceAccount.owner_user_id == owner_id)
        .order_by(ServiceAccount.created_at.desc())
    )
    return list(result.scalars().all())


async def list_all_clients(db: AsyncSession) -> list[ServiceAccount]:
    """List every service account across all owners, newest first. Admin-only."""
    result = await db.execute(select(ServiceAccount).order_by(ServiceAccount.created_at.desc()))
    return list(result.scalars().all())


async def count_clients_for_owner(db: AsyncSession, owner_id: int) -> int:
    """Count active + inactive clients owned by ``owner_id``.

    Used to enforce ``client_max_per_owner`` at create time. Revoked clients
    still count toward the cap; an owner who's hit the limit needs to delete
    a record (or admin-elevated cleanup) before adding new ones.
    """
    total = await db.scalar(
        select(func.count())
        .select_from(ServiceAccount)
        .where(ServiceAccount.owner_user_id == owner_id)
    )
    return int(total or 0)


async def update_last_used(db: AsyncSession, client_id: str, ip: str | None) -> None:
    """Touch ``last_used_at`` + ``last_used_ip`` on a successful token mint."""
    account = await get_client_by_client_id(db, client_id)
    if account is None:
        return
    account.last_used_at = datetime.now(UTC)
    account.last_used_ip = ip
    await db.commit()


def is_client_usable(account: ServiceAccount, *, now: datetime | None = None) -> bool:
    """Return True when this account can mint a token *right now*.

    A client is usable when it's active, not revoked, and not expired. The
    token endpoint must collapse every failure mode into the same
    ``invalid_client`` response, but this helper still distinguishes the
    cases for tests + audit logs.
    """
    when = now or datetime.now(UTC)
    if not account.is_active:
        return False
    if account.revoked_at is not None:
        return False
    if account.expires_at is not None:
        expires_at = account.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= when:
            return False
    return True


def service_account_to_dict(
    account: ServiceAccount, *, plaintext: str | None = None
) -> dict[str, Any]:
    """Serialize a ServiceAccount for an admin API response.

    Pass ``plaintext`` to include the one-time-visible ``client_secret`` in
    the response (creation + rotation paths). Read endpoints never have a
    plaintext to surface, so subsequent calls naturally omit the secret.
    """
    payload: dict[str, Any] = {
        "id": account.id,
        "client_id": account.client_id,
        "name": account.name,
        "description": account.description,
        "scopes": deserialize_scopes(account.scopes),
        "owner_user_id": account.owner_user_id,
        "is_active": account.is_active,
        "expires_at": account.expires_at,
        "created_at": account.created_at,
        "revoked_at": account.revoked_at,
        "last_used_at": account.last_used_at,
        "last_used_ip": account.last_used_ip,
    }
    if plaintext is not None:
        payload["client_secret"] = plaintext
    return payload
