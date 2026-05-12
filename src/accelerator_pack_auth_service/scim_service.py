"""SCIM 2.0 service: user/group provisioning per RFC 7644."""

import hashlib
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import Group, GroupMembership, GroupSource, Role, User

scim_bearer = HTTPBearer()


def hash_scim_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def require_scim_auth(
    credentials: HTTPAuthorizationCredentials = Depends(scim_bearer),
) -> str:
    """Validate SCIM bearer token."""
    if not settings.scim_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="SCIM is not enabled")
    if not settings.scim_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SCIM token not configured",
        )
    token_hash = hash_scim_token(credentials.credentials)
    if token_hash != settings.scim_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid SCIM token")
    return credentials.credentials


# ── SCIM Discovery ───────────────────────────────


SCIM_SERVICE_PROVIDER_CONFIG = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "documentationUri": "https://tools.ietf.org/html/rfc7644",
    "patch": {"supported": False},
    "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
    "filter": {"supported": True, "maxResults": 200},
    "changePassword": {"supported": False},
    "sort": {"supported": False},
    "etag": {"supported": False},
    "authenticationSchemes": [
        {
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication via bearer token",
        }
    ],
}

SCIM_SCHEMAS = [
    {
        "id": "urn:ietf:params:scim:schemas:core:2.0:User",
        "name": "User",
        "description": "User Account",
    },
    {
        "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
        "name": "Group",
        "description": "Group",
    },
]

SCIM_RESOURCE_TYPES = [
    {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/scim/v2/Users",
        "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
    },
    {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group",
        "name": "Group",
        "endpoint": "/scim/v2/Groups",
        "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
    },
]


# ── SCIM User Helpers ────────────────────────────


def user_to_scim(user: User) -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id),
        "userName": user.email,
        "name": {"formatted": user.name},
        "emails": [{"value": user.email, "primary": True}],
        "displayName": user.name,
        "active": user.is_active,
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat() if user.created_at else None,
        },
    }


def group_to_scim(group: Group, members: list[User] | None = None) -> dict:
    result = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": str(group.id),
        "displayName": group.display_name or group.name,
        "externalId": group.external_id,
        "meta": {
            "resourceType": "Group",
            "created": group.created_at.isoformat() if group.created_at else None,
        },
    }
    if members is not None:
        result["members"] = [{"value": str(m.id), "display": m.email} for m in members]
    return result


async def scim_create_user(db: AsyncSession, data: dict) -> User:
    email = data.get("userName", "")
    name = data.get("displayName") or data.get("name", {}).get("formatted", "SCIM User")

    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    user = User(
        email=email,
        name=name,
        password_hash="!scim-provisioned",  # noqa: S106 — sentinel that fails bcrypt.verify; SCIM-provisioned users sign in via SSO only
        role=Role.user,
        is_active=data.get("active", True),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def scim_update_user(db: AsyncSession, user: User, data: dict) -> User:
    if "displayName" in data:
        user.name = data["displayName"]
    elif "name" in data and "formatted" in data["name"]:
        user.name = data["name"]["formatted"]
    if "active" in data:
        user.is_active = data["active"]
    await db.commit()
    await db.refresh(user)
    return user


async def scim_create_group(db: AsyncSession, data: dict) -> Group:
    name = data.get("displayName", "")
    group = Group(
        name=name,
        display_name=name,
        external_id=data.get("externalId"),
        source=GroupSource.scim,
        created_at=datetime.now(UTC),
    )
    db.add(group)
    await db.commit()
    await db.refresh(group)

    # Add members if provided
    for member_data in data.get("members", []):
        user_id = int(member_data["value"])
        db.add(GroupMembership(group_id=group.id, user_id=user_id))
    if data.get("members"):
        await db.commit()

    return group


async def scim_update_group(db: AsyncSession, group: Group, data: dict) -> Group:
    if "displayName" in data:
        group.name = data["displayName"]
        group.display_name = data["displayName"]
    if "externalId" in data:
        group.external_id = data["externalId"]
    group.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(group)
    return group
