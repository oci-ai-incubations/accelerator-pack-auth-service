import enum
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String
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

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.pending)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    collection_permissions = relationship(
        "CollectionPermission", back_populates="user", cascade="all, delete-orphan"
    )


class CollectionPermission(Base):
    __tablename__ = "collection_permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    collection_id = Column(String, nullable=False)
    permission_level = Column(Enum(PermissionLevel), nullable=False, default=PermissionLevel.read)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="collection_permissions")

    __table_args__ = (
        # One permission entry per user per collection
        {"sqlite_autoincrement": True},
    )
