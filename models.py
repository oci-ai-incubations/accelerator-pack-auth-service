import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
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
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Role(enum.StrEnum):
    admin = "admin"
    user = "user"
    reader = "reader"
    pending = "pending"


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
    settings = Column(JSON, nullable=True)
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


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, Identity(always=True), primary_key=True)
    user_id = Column(Integer, nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(255), nullable=True)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
