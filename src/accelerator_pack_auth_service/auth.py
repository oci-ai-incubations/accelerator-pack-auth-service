import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import crypto
from .config import settings
from .crypto import get_active_signing_key, get_key_by_kid
from .database import get_db
from .models import (
    FailedLoginAttempt,
    PrincipalType,
    RefreshToken,
    Role,
    ServiceAccount,
    SigningKeyStatus,
    TokenBlacklist,
    User,
)
from .pack_models import load_active_model

security = HTTPBearer()


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


async def create_access_token(db: AsyncSession, user: User) -> str:
    """Mint an RS256 access token signed by the current active signing key.

    Takes ``db`` so the caller's session — the same one FastAPI's
    ``get_db`` dependency yields — drives the signing-key lookup. Opening a
    fresh ``async_session()`` here would bypass the test fixture override
    and read a different engine that has no signing keys.
    """
    signing_key = await get_active_signing_key(db)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "name": user.name,
        "type": "access",
        "principal_type": PrincipalType.user.value,
        "jti": str(uuid.uuid4()),
        "iss": settings.issuer_url,
        "aud": [settings.pack],
        "exp": datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(
        payload,
        signing_key.private_pem,
        algorithm="RS256",
        headers={"kid": signing_key.kid},
    )


async def create_client_access_token(
    db: AsyncSession, client: ServiceAccount, scopes: list[str]
) -> str:
    """Mint an RS256 access token for an OAuth2 service-account principal.

    Mirrors ``create_access_token`` (same signing-key resolution, same
    audience, same issuer) but stamps ``principal_type=client``, prefixes
    ``sub`` with ``client:`` to avoid collision with user IDs, and substitutes
    ``role`` / ``email`` / ``name`` claims with ``client_id`` + space-joined
    ``scope``. Takes ``db`` so the caller's session — the same one FastAPI
    yields — drives the signing-key lookup.
    """
    signing_key = await get_active_signing_key(db)
    payload = {
        "sub": f"client:{client.client_id}",
        "client_id": client.client_id,
        "scope": " ".join(scopes),
        "type": "access",
        "principal_type": PrincipalType.client.value,
        "jti": str(uuid.uuid4()),
        "iss": settings.issuer_url,
        "aud": [settings.pack],
        "exp": datetime.now(UTC) + timedelta(minutes=settings.client_token_expire_minutes),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(
        payload,
        signing_key.private_pem,
        algorithm="RS256",
        headers={"kid": signing_key.kid},
    )


def create_refresh_token_value() -> str:
    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def store_refresh_token(db: AsyncSession, user_id: int, token_value: str) -> None:
    token = RefreshToken(
        user_id=user_id,
        token_hash=hash_refresh_token(token_value),
        expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(token)
    await db.commit()


async def validate_refresh_token(db: AsyncSession, token_value: str) -> RefreshToken | None:
    token_hash = hash_refresh_token(token_value)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == 0,
            RefreshToken.expires_at > datetime.now(UTC),
        )
    )
    return result.scalar_one_or_none()


async def revoke_user_tokens(db: AsyncSession, user_id: int) -> None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked == 0)
    )
    for token in result.scalars().all():
        token.revoked = True
    await db.commit()


async def decode_token(db: AsyncSession, token: str) -> dict:
    """Verify an RS256 token by resolving its ``kid`` against signing_keys.

    Unknown or revoked kids are rejected before signature verification so a
    revoked key can't validate one more token. ``rotating_out`` keys are
    accepted only inside the 24h grace window — past the cutoff their tokens
    fail the same way revoked-key tokens do. Issuer is always verified
    (``settings.issuer_url`` is required at startup; see ``Settings.model_post_init``).
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing kid header"
        )

    signing_key = await get_key_by_kid(db, kid)
    if signing_key is None or signing_key.status == SigningKeyStatus.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked signing key"
        )
    if signing_key.status == SigningKeyStatus.rotating_out:
        rotated_at = signing_key.rotated_at
        if rotated_at is not None and rotated_at.tzinfo is None:
            rotated_at = rotated_at.replace(tzinfo=UTC)
        if rotated_at is None or rotated_at + crypto.ROTATING_OUT_GRACE <= datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    try:
        return jwt.decode(
            token,
            signing_key.public_pem,
            algorithms=["RS256"],
            issuer=settings.issuer_url,
            options={"verify_iss": True, "verify_aud": False},
        )
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e


async def is_token_blacklisted(db: AsyncSession, jti: str) -> bool:
    result = await db.execute(select(TokenBlacklist).where(TokenBlacklist.jti == jti))
    return result.scalar_one_or_none() is not None


async def blacklist_token(db: AsyncSession, jti: str, expires_at: datetime) -> None:
    entry = TokenBlacklist(jti=jti, expires_at=expires_at)
    db.add(entry)
    await db.commit()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = await decode_token(db, credentials.credentials)
    if payload.get("type") == "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh tokens cannot be used for API access",
        )
    jti = payload.get("jti")
    if jti and await is_token_blacklisted(db, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )
    user_id = int(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != Role.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_permission(permission_codename: str):
    """Factory: dependency that checks a permission via the full RBAC engine.

    Consults role-based permissions, direct grants, and resource ownership
    (see permission_service.check_permission). Use this for permissions tied
    to specific resources or grant-based access.
    """

    async def _check(
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        from .permission_service import check_permission

        has_perm = await check_permission(db, user, permission_codename)
        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission_codename}",
            )
        return user

    return _check


def require_pack_permission(permission_codename: str):
    """Factory: dependency that checks a permission against the active pack model.

    Faster than `require_permission` because it does not query the DB —
    resolves the user's role to the static role→permission map declared by
    the active PackAuthModel (selected by AUTH_PACK). Use for pack-static
    permission checks; use `require_permission` for resource- or grant-scoped
    checks.

    `admin` role always passes (matches legacy behavior).
    """

    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role == Role.admin:
            return user
        pack_model = load_active_model(settings.pack)
        effective_perms = pack_model.permissions_for_role(user.role.value)
        if permission_codename not in effective_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission_codename}",
            )
        return user

    return _check


async def record_failed_login(db: AsyncSession, email: str, ip_address: str | None = None) -> None:
    attempt = FailedLoginAttempt(email=email, ip_address=ip_address)
    db.add(attempt)
    await db.commit()


async def check_account_lockout(db: AsyncSession, email: str) -> None:
    window = datetime.now(UTC) - timedelta(minutes=settings.account_lockout_duration_minutes)
    count = await db.scalar(
        select(func.count())
        .select_from(FailedLoginAttempt)
        .where(
            FailedLoginAttempt.email == email,
            FailedLoginAttempt.attempted_at > window,
        )
    )
    if count >= settings.account_lockout_threshold:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to too many failed login attempts",
        )


async def clear_failed_attempts(db: AsyncSession, email: str) -> None:
    await db.execute(delete(FailedLoginAttempt).where(FailedLoginAttempt.email == email))
    await db.commit()


async def enforce_session_limit(db: AsyncSession, user_id: int) -> None:
    result = await db.execute(
        select(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked == 0)
        .order_by(RefreshToken.created_at.desc())
    )
    active_tokens = result.scalars().all()
    if len(active_tokens) >= settings.max_concurrent_sessions:
        for token in active_tokens[settings.max_concurrent_sessions - 1 :]:
            token.revoked = True
        await db.commit()


async def log_audit(
    db: AsyncSession,
    user_id: int | None,
    action: str,
    target: str = "",
    *,
    principal_type: PrincipalType | str | None = None,
    principal_id: str | None = None,
) -> None:
    """Write an audit log entry attributed to either a user or a client principal.

    ``user_id`` continues to populate ``actor_user_id`` for user-typed actors
    so existing queries keep working. ``principal_type`` + ``principal_id``
    cover client-driven actions where ``user_id`` is None — the OAuth2 token
    endpoint, scheduled jobs run on behalf of a client, etc.
    """
    from .models import AuditLog, AuditResult

    resolved_principal_type: str | None
    if principal_type is None:
        resolved_principal_type = PrincipalType.user.value if user_id is not None else None
    elif isinstance(principal_type, PrincipalType):
        resolved_principal_type = principal_type.value
    else:
        resolved_principal_type = str(principal_type)

    resolved_principal_id = principal_id
    if resolved_principal_id is None and user_id is not None:
        resolved_principal_id = str(user_id)

    entry = AuditLog(
        user_id=user_id,
        action=action,
        target=target,
        # Phase 5 structured fields
        timestamp=datetime.now(UTC),
        event_type=action,
        actor_user_id=user_id,
        actor_principal_type=resolved_principal_type,
        actor_principal_id=resolved_principal_id,
        result=AuditResult.success,
        created_at=datetime.now(UTC),
    )
    db.add(entry)
    await db.commit()
