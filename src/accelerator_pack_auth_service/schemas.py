import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator

from .models import PermissionLevel, ProviderType, Role

# Service-account expiry caps. Past dates are nonsensical (the client would be
# unusable on creation); 10-year ceilings prevent the year-9999 surprise that
# Pydantic's open-ended ``datetime`` field otherwise allows.
_SERVICE_ACCOUNT_MAX_EXPIRY = timedelta(days=3650)
# RFC 6749 §3.3 scope-string VSCHAR character set: printable ASCII except
# ``"`` (0x22) and ``\`` (0x5C). Covers the URL-shaped scopes that real-world
# OIDC providers emit — Google ("https://www.googleapis.com/auth/userinfo.email"),
# Oracle IDCS ("https://cuopt.example.com/api/cuopt.solve"), Microsoft Entra
# ("access_as_user"), Auth0 ("read:users").
_SCOPE_NAME_PATTERN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
# Per-entry length cap (256 chars) matches the longer URL-form scopes that
# OIDC/IDCS emit without leaving room for a single oversized entry to blow up
# storage or logging budgets.
_SCOPE_NAME_MAX_LENGTH = 256
# Caps the scopes list so an attacker can't post 100k entries and stall the
# server during JSON-encoding + DB write.
_SERVICE_ACCOUNT_MAX_SCOPES = 64


# ── Auth ──────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    # Optional RFC 6749 §3.3 space-separated scope request. Caps the string
    # at 2048 chars so a single oversized payload can't blow up logging /
    # storage; each parsed entry is then per-element regex-validated below.
    scope: str | None = Field(default=None, max_length=2048)

    @field_validator("scope")
    @classmethod
    def _validate_scope_string(cls, v: str | None) -> str | None:
        if v is None:
            return None
        for entry in v.split():
            _ensure_valid_scope_entry(entry)
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 — OAuth 2.0 token-type literal, not a credential
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


# ── OAuth2 Service Accounts (Spec 002) ──────────────
def _ensure_valid_scope_entry(entry: object) -> None:
    """Validate a single scope-list entry against RFC 6749 §3.3 VSCHAR.

    Reject empty strings, non-strings, oversized entries, and any entry
    containing forbidden control / double-quote / backslash characters.
    Hoisted out so ``LoginRequest.scope`` and the service-account scope-list
    validators share one source of truth (and one consistent error message).
    """
    if not isinstance(entry, str):
        raise ValueError("scope entries must be strings")
    if not entry:
        raise ValueError("scope entries must be non-empty")
    if len(entry) > _SCOPE_NAME_MAX_LENGTH:
        raise ValueError(f"scope entries must be at most {_SCOPE_NAME_MAX_LENGTH} characters")
    if not _SCOPE_NAME_PATTERN.fullmatch(entry):
        raise ValueError(
            "scope entries must be RFC 6749 §3.3 VSCHAR (printable ASCII except '\"' and '\\')"
        )


def _validate_scope_list(scopes: list[str] | None) -> list[str] | None:
    """Reject scope entries that don't match RFC 6749 §3.3 shape + cap length."""
    if scopes is None:
        return None
    for entry in scopes:
        _ensure_valid_scope_entry(entry)
    return scopes


def _normalize_expires_at(value: Any) -> Any:
    """Coerce naive datetimes to UTC so downstream comparisons stay timezone-aware."""
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _validate_expires_at_window(value: datetime | None) -> datetime | None:
    """Reject past dates and dates more than 10 years in the future."""
    if value is None:
        return None
    now = datetime.now(UTC)
    if value < now:
        raise ValueError("expires_at must be in the future")
    if value > now + _SERVICE_ACCOUNT_MAX_EXPIRY:
        raise ValueError("expires_at must be within 10 years")
    return value


class ServiceAccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    scopes: list[str] = Field(default_factory=list, max_length=_SERVICE_ACCOUNT_MAX_SCOPES)
    expires_at: datetime | None = None

    @field_validator("scopes")
    @classmethod
    def _validate_scopes(cls, v: list[str]) -> list[str]:
        return _validate_scope_list(v) or []

    @field_validator("expires_at", mode="before")
    @classmethod
    def _coerce_naive_expires_at(cls, v: Any) -> Any:
        return _normalize_expires_at(v)

    @field_validator("expires_at")
    @classmethod
    def _check_expires_at_window(cls, v: datetime | None) -> datetime | None:
        return _validate_expires_at_window(v)


class ServiceAccountUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    scopes: list[str] | None = Field(default=None, max_length=_SERVICE_ACCOUNT_MAX_SCOPES)
    expires_at: datetime | None = None
    is_active: bool | None = None

    @field_validator("scopes")
    @classmethod
    def _validate_scopes(cls, v: list[str] | None) -> list[str] | None:
        return _validate_scope_list(v)

    @field_validator("expires_at", mode="before")
    @classmethod
    def _coerce_naive_expires_at(cls, v: Any) -> Any:
        return _normalize_expires_at(v)

    @field_validator("expires_at")
    @classmethod
    def _check_expires_at_window(cls, v: datetime | None) -> datetime | None:
        return _validate_expires_at_window(v)


class ServiceAccountResponse(BaseModel):
    """Read-side view of a service account — secret never included."""

    id: int
    client_id: str
    name: str
    description: str | None
    scopes: list[str]
    # Nullable: env-seeded (bootstrap) service accounts have no human owner.
    owner_user_id: int | None
    is_active: bool
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    last_used_ip: str | None


class ServiceAccountWithSecret(ServiceAccountResponse):
    """One-time view returned by create + rotate. ``client_secret`` is plaintext."""

    client_secret: str


# ── Pack Scopes (Spec 003) ──────────────────────────
class ScopeDescription(BaseModel):
    """One scope entry returned by GET /auth/scopes — codename + human description."""

    codename: str
    description: str


class PackScopesResponse(BaseModel):
    """Response shape for GET /auth/scopes — drives admin-UI scope pickers."""

    pack_id: str
    scopes: list[ScopeDescription]
