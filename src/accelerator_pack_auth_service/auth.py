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

from .config import settings
from .database import get_db
from .models import FailedLoginAttempt, RefreshToken, Role, TokenBlacklist, User

security = HTTPBearer()


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_access_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "name": user.name,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


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
            RefreshToken.revoked.is_(False),
            RefreshToken.expires_at > datetime.now(UTC),
        )
    )
    return result.scalar_one_or_none()


async def revoke_user_tokens(db: AsyncSession, user_id: int) -> None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
    )
    for token in result.scalars().all():
        token.revoked = True
    await db.commit()


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
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
    payload = decode_token(credentials.credentials)
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
    """Factory that returns a FastAPI dependency checking a specific permission."""

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
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .order_by(RefreshToken.created_at.desc())
    )
    active_tokens = result.scalars().all()
    if len(active_tokens) >= settings.max_concurrent_sessions:
        for token in active_tokens[settings.max_concurrent_sessions - 1 :]:
            token.revoked = True
        await db.commit()


async def log_audit(db: AsyncSession, user_id: int, action: str, target: str = "") -> None:
    from .models import AuditLog, AuditResult

    entry = AuditLog(
        user_id=user_id,
        action=action,
        target=target,
        # Phase 5 structured fields
        timestamp=datetime.now(UTC),
        event_type=action,
        actor_user_id=user_id,
        result=AuditResult.success,
        created_at=datetime.now(UTC),
    )
    db.add(entry)
    await db.commit()
