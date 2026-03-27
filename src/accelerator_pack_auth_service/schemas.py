from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from .models import PermissionLevel, ProviderType, Role


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


# ── Identity Providers (Phase 3) ─────────────────
class ProviderCreate(BaseModel):
    type: ProviderType
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    config: dict = {}
    tenant_id: int | None = None
    is_active: bool = True
    priority: int = 0


class ProviderUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    is_active: bool | None = None
    priority: int | None = None


class ProviderResponse(BaseModel):
    id: int
    type: ProviderType
    name: str
    slug: str
    config: dict
    tenant_id: int | None
    is_active: bool
    priority: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ClaimMappingCreate(BaseModel):
    claim_key: str = Field(min_length=1, max_length=255)
    claim_value_pattern: str = Field(min_length=1, max_length=255)
    role_id: int
    priority: int = 0
    is_regex: bool = False


class ClaimMappingResponse(BaseModel):
    id: int
    provider_id: int
    claim_key: str
    claim_value_pattern: str
    role_id: int
    priority: int
    is_regex: bool

    model_config = {"from_attributes": True}
