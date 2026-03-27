"""Permission evaluation engine for fine-grained RBAC.

Checks permissions via: role-based permissions → direct grants → resource ownership.
Falls back to legacy User.role enum for backward compatibility.
"""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import (
    DbRole,
    DirectGrant,
    Permission,
    ResourceOwnership,
    Role,
    RolePermission,
    User,
    UserRole,
)

# System permissions seeded on startup
SYSTEM_PERMISSIONS = [
    ("users:list", "List all users", "users"),
    ("users:read", "Read user details", "users"),
    ("users:update", "Update user details", "users"),
    ("users:delete", "Deactivate a user", "users"),
    ("collections:read", "Read collections", "collections"),
    ("collections:write", "Upload to collections", "collections"),
    ("collections:manage", "Manage collection permissions", "collections"),
    ("collections:delete", "Delete collections", "collections"),
    ("roles:list", "List roles", "roles"),
    ("roles:create", "Create roles", "roles"),
    ("roles:read", "Read role details", "roles"),
    ("roles:update", "Update roles", "roles"),
    ("roles:delete", "Delete roles", "roles"),
    ("permissions:list", "List all permissions", "permissions"),
    ("permissions:check", "Check permission for a user", "permissions"),
]

# System roles and their default permissions
SYSTEM_ROLES = {
    "admin": {
        "description": "Full access to all resources",
        "permissions": "*",  # all permissions
    },
    "user": {
        "description": "Standard user with read/write access to assigned collections",
        "permissions": ["collections:read", "collections:write"],
    },
    "reader": {
        "description": "Read-only access to assigned collections",
        "permissions": ["collections:read"],
    },
    "pending": {
        "description": "Awaiting admin approval — no access",
        "permissions": [],
    },
}


async def seed_roles_and_permissions(db: AsyncSession) -> None:
    """Seed system permissions and roles if they don't exist."""
    # Seed permissions
    for codename, description, resource_type in SYSTEM_PERMISSIONS:
        existing = await db.execute(select(Permission).where(Permission.codename == codename))
        if not existing.scalar_one_or_none():
            db.add(
                Permission(codename=codename, description=description, resource_type=resource_type)
            )
    await db.commit()

    # Load all permissions for role assignment
    result = await db.execute(select(Permission))
    all_perms = {p.codename: p for p in result.scalars().all()}

    # Seed roles
    for role_name, role_def in SYSTEM_ROLES.items():
        existing = await db.execute(
            select(DbRole).where(DbRole.name == role_name, DbRole.is_system.is_(True))
        )
        role = existing.scalar_one_or_none()
        if not role:
            role = DbRole(
                name=role_name,
                description=role_def["description"],
                is_system=True,
                is_default=(role_name == "pending"),
                created_at=datetime.now(UTC),
            )
            db.add(role)
            await db.commit()
            await db.refresh(role)

        # Assign permissions to role
        perm_codes = role_def["permissions"]
        if perm_codes == "*":
            perm_codes = list(all_perms.keys())

        for codename in perm_codes:
            perm = all_perms.get(codename)
            if not perm:
                continue
            existing_rp = await db.execute(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == perm.id,
                )
            )
            if not existing_rp.scalar_one_or_none():
                db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    await db.commit()


async def check_permission(
    db: AsyncSession,
    user: User,
    permission_codename: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    tenant_id: int | None = None,
) -> bool:
    """Evaluate whether a user has a specific permission.

    Check order:
    1. Legacy admin role bypass (User.role == admin)
    2. Role-based permissions (via user_roles → role_permissions → permissions)
    3. Direct grants
    4. Resource ownership (if resource_type + resource_id provided)
    """
    # 1. Legacy admin bypass
    if user.role == Role.admin:
        return True

    # 2. Check role-based permissions via the new RBAC model
    role_check = await db.execute(
        select(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(DbRole, DbRole.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == DbRole.id)
        .where(
            UserRole.user_id == user.id,
            Permission.codename == permission_codename,
        )
    )
    if role_check.scalar_one_or_none():
        return True

    # Also check via legacy role → system role mapping
    system_role = await db.execute(
        select(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(DbRole, DbRole.id == RolePermission.role_id)
        .where(
            DbRole.name == user.role.value,
            DbRole.is_system.is_(True),
            Permission.codename == permission_codename,
        )
    )
    if system_role.scalar_one_or_none():
        return True

    # 3. Check direct grants
    grant_query = select(DirectGrant).where(
        DirectGrant.user_id == user.id,
    )
    # Join to find the permission by codename
    grant_query = (
        select(DirectGrant)
        .join(Permission, Permission.id == DirectGrant.permission_id)
        .where(
            DirectGrant.user_id == user.id,
            Permission.codename == permission_codename,
        )
    )
    if resource_type:
        grant_query = grant_query.where(DirectGrant.resource_type == resource_type)
    if resource_id:
        grant_query = grant_query.where(DirectGrant.resource_id == resource_id)

    grant_result = await db.execute(grant_query)
    if grant_result.scalar_one_or_none():
        return True

    # 4. Check resource ownership
    if resource_type and resource_id:
        ownership = await db.execute(
            select(ResourceOwnership).where(
                ResourceOwnership.resource_type == resource_type,
                ResourceOwnership.resource_id == resource_id,
                ResourceOwnership.owner_user_id == user.id,
            )
        )
        if ownership.scalar_one_or_none():
            return True

    return False
