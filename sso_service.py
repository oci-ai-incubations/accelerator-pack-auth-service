"""SSO service: JIT provisioning, claim-to-role mapping, token bridge."""

import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import create_access_token, create_refresh_token_value, store_refresh_token
from models import (
    ClaimRoleMapping,
    DbRole,
    ExternalIdentity,
    IdentityProvider,
    Role,
    User,
    UserRole,
)


async def jit_provision_user(
    db: AsyncSession,
    provider: IdentityProvider,
    external_id: str,
    email: str,
    name: str,
    raw_claims: dict | None = None,
) -> tuple[User, bool]:
    """Just-In-Time provision a user from SSO.

    Returns (user, created) — created=True if this is a new user.
    """
    # Check for existing external identity link
    result = await db.execute(
        select(ExternalIdentity).where(
            ExternalIdentity.provider_id == provider.id,
            ExternalIdentity.external_id == external_id,
        )
    )
    ext_identity = result.scalar_one_or_none()

    if ext_identity:
        # Existing user — update last login and claims
        ext_identity.last_login_at = datetime.now(UTC)
        ext_identity.raw_claims = raw_claims
        await db.commit()

        user_result = await db.execute(select(User).where(User.id == ext_identity.user_id))
        user = user_result.scalar_one()
        return user, False

    # Check if a user with this email already exists (link accounts)
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()

    created = False
    if not user:
        # Create new user with default role
        user = User(
            email=email,
            name=name,
            password_hash="!sso-only",  # Cannot login with password
            role=Role.user,  # SSO users get 'user' role by default
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        created = True

    # Link external identity
    ext_identity = ExternalIdentity(
        user_id=user.id,
        provider_id=provider.id,
        external_id=external_id,
        email=email,
        raw_claims=raw_claims,
        last_login_at=datetime.now(UTC),
    )
    db.add(ext_identity)
    await db.commit()

    return user, created


async def apply_claim_mappings(
    db: AsyncSession,
    provider: IdentityProvider,
    user: User,
    claims: dict,
) -> list[str]:
    """Apply claim-to-role mappings for a provider. Returns list of assigned role names."""
    result = await db.execute(
        select(ClaimRoleMapping)
        .where(ClaimRoleMapping.provider_id == provider.id)
        .order_by(ClaimRoleMapping.priority.desc())
    )
    mappings = result.scalars().all()
    assigned_roles = []

    for mapping in mappings:
        claim_value = claims.get(mapping.claim_key)
        if claim_value is None:
            continue

        # Support claim values that are lists (e.g., groups)
        values = claim_value if isinstance(claim_value, list) else [claim_value]

        for val in values:
            val_str = str(val)
            matched = False
            if mapping.is_regex:
                matched = bool(re.search(mapping.claim_value_pattern, val_str))
            else:
                matched = val_str == mapping.claim_value_pattern

            if matched:
                # Assign role if not already assigned
                existing = await db.execute(
                    select(UserRole).where(
                        UserRole.user_id == user.id,
                        UserRole.role_id == mapping.role_id,
                    )
                )
                if not existing.scalar_one_or_none():
                    db.add(
                        UserRole(
                            user_id=user.id,
                            role_id=mapping.role_id,
                            created_at=datetime.now(UTC),
                        )
                    )
                    # Get role name
                    role_result = await db.execute(
                        select(DbRole).where(DbRole.id == mapping.role_id)
                    )
                    role = role_result.scalar_one_or_none()
                    if role:
                        assigned_roles.append(role.name)
                break  # First match per claim key wins

    if assigned_roles:
        await db.commit()
    return assigned_roles


async def issue_sso_tokens(
    db: AsyncSession,
    user: User,
) -> tuple[str, str]:
    """Issue internal JWT tokens after SSO authentication."""
    access_token = create_access_token(user)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)
    return access_token, refresh_value
