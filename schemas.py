from datetime import datetime

from pydantic import BaseModel, EmailStr

from models import PermissionLevel, Role


# ── Auth ──────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"


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
