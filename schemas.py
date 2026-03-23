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


# ── Conversations ─────────────────────────────────
class ConversationCreate(BaseModel):
    external_id: str = Field(max_length=64)
    title: str = Field(max_length=255, default="New Chat")
    messages: str = "[]"  # JSON string


class ConversationUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    messages: str | None = None  # JSON string


class ConversationResponse(BaseModel):
    id: int
    external_id: str
    title: str
    messages: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
