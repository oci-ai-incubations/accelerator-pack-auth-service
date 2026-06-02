import enum
import json as json_lib
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class JSONText(TypeDecorator):
    """JSON stored as Text — works on all databases including Oracle."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json_lib.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return json_lib.loads(value)
        return None


class Base(DeclarativeBase):
    pass


class Role(enum.StrEnum):
    admin = "admin"
    user = "user"
    reader = "reader"
    pending = "pending"


class PrincipalType(enum.StrEnum):
    """Discriminator for the JWT ``principal_type`` claim.

    Separates human callers (``user`` — fronted by login + refresh tokens) from
    machine callers (``client`` — OAuth2 client_credentials grant). Pack BEs
    branch on this when distinguishing role-gated routes (humans only) from
    scope-gated routes (either).
    """

    user = "user"
    client = "client"


class PermissionLevel(enum.StrEnum):
    read = "read"
    write = "write"
    manage = "manage"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, Identity(always=True), primary_key=True)
    email = Column(String(320), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.pending)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    # JSON-encoded list of scope codenames. NULL means "use the role's full
    # permission set" — the common case. Non-NULL pins this user to a narrower
    # default scope set (rare; e.g. a power user who wants to limit their own
    # default token blast radius). Spec 003.
    allowed_scopes = Column(Text, nullable=True)

    collection_permissions = relationship(
        "CollectionPermission", back_populates="user", cascade="all, delete-orphan"
    )
    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class CollectionPermission(Base):
    __tablename__ = "collection_permissions"

    id = Column(Integer, Identity(always=True), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    collection_id = Column(String(255), nullable=False)
    permission_level = Column(Enum(PermissionLevel), nullable=False, default=PermissionLevel.read)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    user = relationship("User", back_populates="collection_permissions")

    __table_args__ = (
        Index("ix_collection_perm_user_col", "user_id", "collection_id", unique=True),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, Identity(always=True), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    user = relationship("User", back_populates="refresh_tokens")


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, Identity(always=True), primary_key=True)
    jti = Column(String(36), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))


class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"

    id = Column(Integer, Identity(always=True), primary_key=True)
    email = Column(String(320), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    attempted_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))


# ── Phase 2: Fine-Grained Authorization ──────────


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, Identity(always=True), primary_key=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    settings = Column(JSONText, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))


class DbRole(Base):
    __tablename__ = "roles"

    id = Column(Integer, Identity(always=True), primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    is_system = Column(Boolean, nullable=False, default=False)
    is_default = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    permissions = relationship(
        "RolePermission", back_populates="role", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_role_tenant_name"),)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, Identity(always=True), primary_key=True)
    codename = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(500), nullable=True)
    resource_type = Column(String(100), nullable=True)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(
        Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )

    role = relationship("DbRole", back_populates="permissions")
    permission = relationship("Permission")


class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(Integer, Identity(always=True), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    scope_type = Column(String(50), nullable=True)
    scope_id = Column(String(255), nullable=True)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    user = relationship("User", foreign_keys=[user_id])
    role = relationship("DbRole")

    __table_args__ = (
        Index("ix_user_role_user_id", "user_id"),
        Index("ix_user_role_role_id", "role_id"),
    )


class DirectGrant(Base):
    __tablename__ = "direct_grants"

    id = Column(Integer, Identity(always=True), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    permission_id = Column(
        Integer, ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    user = relationship("User", foreign_keys=[user_id])
    permission = relationship("Permission")

    __table_args__ = (Index("ix_direct_grant_user_id", "user_id"),)


class ResourceOwnership(Base):
    __tablename__ = "resource_ownership"

    id = Column(Integer, Identity(always=True), primary_key=True)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=False)
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)

    owner = relationship("User")

    __table_args__ = (
        UniqueConstraint(
            "resource_type", "resource_id", "tenant_id", name="uq_resource_owner_tenant"
        ),
    )


# ── Phase 3: OIDC & SAML ─────────────────────────


class ProviderType(enum.StrEnum):
    oidc = "oidc"
    saml = "saml"


class IdentityProvider(Base):
    __tablename__ = "identity_providers"

    id = Column(Integer, Identity(always=True), primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    type = Column(Enum(ProviderType), nullable=False)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    config = Column(JSONText, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    priority = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    claim_mappings = relationship(
        "ClaimRoleMapping", back_populates="provider", cascade="all, delete-orphan"
    )


class ExternalIdentity(Base):
    __tablename__ = "external_identities"

    id = Column(Integer, Identity(always=True), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider_id = Column(
        Integer, ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False
    )
    external_id = Column(String(255), nullable=False)
    email = Column(String(320), nullable=True)
    raw_claims = Column(JSONText, nullable=True)
    last_login_at = Column(DateTime, nullable=True)

    user = relationship("User")
    provider = relationship("IdentityProvider")

    __table_args__ = (
        UniqueConstraint("provider_id", "external_id", name="uq_provider_external_id"),
    )


class ClaimRoleMapping(Base):
    __tablename__ = "claim_role_mappings"

    id = Column(Integer, Identity(always=True), primary_key=True)
    provider_id = Column(
        Integer, ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False
    )
    claim_key = Column(String(255), nullable=False)
    claim_value_pattern = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    priority = Column(Integer, nullable=False, default=0)
    is_regex = Column(Boolean, nullable=False, default=False)

    provider = relationship("IdentityProvider", back_populates="claim_mappings")
    role = relationship("DbRole")


# ── Phase 4: SCIM Groups ─────────────────────────


class GroupSource(enum.StrEnum):
    local = "local"
    scim = "scim"
    jit = "jit"


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, Identity(always=True), primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=True)
    description = Column(String(500), nullable=True)
    external_id = Column(String(255), nullable=True)
    source = Column(Enum(GroupSource), nullable=False, default=GroupSource.local)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, nullable=True, onupdate=lambda: datetime.now(UTC))

    memberships = relationship(
        "GroupMembership", back_populates="group", cascade="all, delete-orphan"
    )
    roles = relationship("GroupRole", back_populates="group", cascade="all, delete-orphan")


class GroupMembership(Base):
    __tablename__ = "group_memberships"

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)

    group = relationship("Group", back_populates="memberships")
    user = relationship("User")


class GroupRole(Base):
    __tablename__ = "group_roles"

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)

    group = relationship("Group", back_populates="roles")
    role = relationship("DbRole")


class SsoState(Base):
    """Single-use SSO state token bound to a provider, redirect_uri, and nonce.

    Issued at ``/auth/sso/{slug}/authorize`` and verified at the callback in
    ``/auth/sso/{slug}/token``. Single-use semantics protect against CSRF on
    the IdP callback (state) and OIDC ID-token replay (nonce). Expired or
    consumed rows stay in the table for audit replay-detection until the next
    background sweep; deletion on consume keeps the table small in the common
    case.
    """

    __tablename__ = "sso_state"

    state = Column(String(128), primary_key=True)
    nonce = Column(String(64), nullable=False)
    provider_id = Column(
        Integer, ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False
    )
    redirect_uri = Column(String(2048), nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime, nullable=False, index=True)


class SigningKeyStatus(enum.StrEnum):
    active = "active"
    rotating_out = "rotating_out"
    revoked = "revoked"


class SigningKey(Base):
    __tablename__ = "signing_keys"

    id = Column(Integer, Identity(always=True), primary_key=True)
    kid = Column(String(64), nullable=False, unique=True, index=True)
    algorithm = Column(String(16), nullable=False, default="RS256")
    public_pem = Column(Text, nullable=False)
    private_pem = Column(Text, nullable=False)
    status = Column(
        Enum(SigningKeyStatus),
        nullable=False,
        default=SigningKeyStatus.active,
        index=True,
    )
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    rotated_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)


class AuditResult(enum.StrEnum):
    success = "success"
    failure = "failure"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, Identity(always=True), primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC), index=True)
    event_type = Column(String(100), nullable=False, index=True)
    actor_user_id = Column(Integer, nullable=True)
    actor_email = Column(String(320), nullable=True)
    # Principal-typed actor fields supersede actor_user_id for client-driven
    # actions. actor_user_id stays populated for user-typed actors so existing
    # queries / dashboards keep working without an immediate migration.
    actor_principal_type = Column(String(16), nullable=True)
    actor_principal_id = Column(String(128), nullable=True)
    target_type = Column(String(100), nullable=True)
    target_id = Column(String(255), nullable=True)
    tenant_id = Column(Integer, nullable=True)
    details = Column(JSONText, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    result = Column(Enum(AuditResult), nullable=False, default=AuditResult.success)
    # Legacy fields kept for backward compat
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=True)
    target = Column(String(255), nullable=True)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=True, default=lambda: datetime.now(UTC))


class ServiceAccount(Base):
    """OAuth2 client_credentials principal — machine-to-machine identity.

    Created by an admin via the /auth/admin/clients API; authenticated against
    the token endpoint with a bcrypt-hashed shared secret. The plaintext
    secret is shown exactly once at creation (or rotation) and is never
    persisted. Tokens minted for this account carry ``principal_type=client``
    and ``sub=client:<client_id>``.
    """

    __tablename__ = "service_accounts"

    id = Column(Integer, Identity(always=True), primary_key=True)
    client_id = Column(String(64), unique=True, nullable=False, index=True)
    client_secret_hash = Column(String(128), nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    # JSON-encoded list of scope codenames. Empty string = no scopes granted.
    scopes = Column(Text, nullable=False, default="")
    # Nullable: env-seeded (bootstrap) service accounts have no human owner.
    # Admin-API-created accounts still set this to the creating admin's id.
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    revoked_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    last_used_ip = Column(String(45), nullable=True)
