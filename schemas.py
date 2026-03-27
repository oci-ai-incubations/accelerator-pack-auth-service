from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from models import PermissionLevel, Role


# ── Auth ──────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires
    user: "UserResponse"


class RefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    token: str


# ── Users ─────────────────────────────────────────
class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    role: Role
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UpdateUserRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    name: str | None = None


# ── Collection Permissions ────────────────────────
class CollectionPermissionRequest(BaseModel):
    user_id: int
    permission_level: PermissionLevel = PermissionLevel.read


class CollectionPermissionResponse(BaseModel):
    id: int
    user_id: int
    collection_id: str
    permission_level: PermissionLevel
    user_email: str | None = None

    model_config = {"from_attributes": True}


class MyCollectionAccess(BaseModel):
    collection_id: str
    permission_level: PermissionLevel


# ── Roles & Permissions (Phase 2) ────────────────
class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None
    tenant_id: int | None = None


class RoleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    is_default: bool | None = None


class RoleResponse(BaseModel):
    id: int
    name: str
    description: str | None
    is_system: bool
    is_default: bool
    tenant_id: int | None
    permissions: list[str] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class PermissionResponse(BaseModel):
    id: int
    codename: str
    description: str | None
    resource_type: str | None

    model_config = {"from_attributes": True}


class RolePermissionUpdate(BaseModel):
    permission_codenames: list[str]


class UserRoleAssign(BaseModel):
    role_id: int
    tenant_id: int | None = None
    scope_type: str | None = None
    scope_id: str | None = None


class UserRoleResponse(BaseModel):
    id: int
    user_id: int
    role_id: int
    role_name: str
    tenant_id: int | None
    scope_type: str | None
    scope_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PermissionCheck(BaseModel):
    user_id: int
    permission: str
    resource_type: str | None = None
    resource_id: str | None = None


class PermissionCheckResult(BaseModel):
    allowed: bool
    permission: str
    user_id: int
