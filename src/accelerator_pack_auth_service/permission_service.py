"""Permission evaluation engine for fine-grained RBAC.

Checks permissions via: role-based permissions → direct grants → resource ownership.
Falls back to legacy User.role enum for backward compatibility.

Seeding is driven by the active `PackAuthModel` (selected by AUTH_PACK env var).
See `pack_models/` for the per-pack RBAC definitions.
"""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import (
    DbRole,
    DirectGrant,
    Permission,
    ResourceOwnership,
    Role,
    RolePermission,
    User,
    UserRole,
)
from .pack_models import PackAuthModel, load_active_model

# Human-readable descriptions for known permission keys. Permissions seeded
# from a pack model that aren't in this map get an auto-generated description.
PERMISSION_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    # paas_rag legacy
    "users:list": ("List all users", "users"),
    "users:read": ("Read user details", "users"),
    "users:update": ("Update user details", "users"),
    "users:delete": ("Deactivate a user", "users"),
    "collections:read": ("Read collections", "collections"),
    "collections:write": ("Upload to collections", "collections"),
    "collections:manage": ("Manage collection permissions", "collections"),
    "collections:delete": ("Delete collections", "collections"),
    "roles:list": ("List roles", "roles"),
    "roles:create": ("Create roles", "roles"),
    "roles:read": ("Read role details", "roles"),
    "roles:update": ("Update roles", "roles"),
    "roles:delete": ("Delete roles", "roles"),
    "permissions:list": ("List all permissions", "permissions"),
    "permissions:check": ("Check permission for a user", "permissions"),
    # cuopt
    "cuopt.solve": ("Submit a routing solve request", "cuopt"),
    "cuopt.view": ("View routing solutions", "cuopt"),
    "chat.use": ("Use the GenAI chat assistant", "chat"),
    "weather.view": ("View weather data for routes", "weather"),
    "config.read": ("Read runtime configuration", "config"),
    # cross-pack admin
    "admin.users.manage": ("Manage users", "admin"),
    "admin.config.write": ("Write runtime configuration / API keys", "admin"),
    "admin.features.toggle": ("Enable/disable optional features", "admin"),
    "admin.audit.view": ("View the audit log", "admin"),
}

# Role descriptions for known roles. Roles outside this map get a generic
# auto-generated description at seed time.
ROLE_DESCRIPTIONS: dict[str, str] = {
    "admin": "Full access to all resources",
    "user": "Standard user",
    "reader": "Read-only access",
    "pending": "Awaiting admin approval — no access",
}


def _permission_meta(codename: str) -> tuple[str, str]:
    """Return (description, resource_type) for a permission key.

    Falls back to a generic description + the prefix-before-colon-or-dot as
    the resource type if the key is not in PERMISSION_DESCRIPTIONS.
    """
    if codename in PERMISSION_DESCRIPTIONS:
        return PERMISSION_DESCRIPTIONS[codename]
    if ":" in codename:
        resource_type = codename.split(":", 1)[0]
    elif "." in codename:
        resource_type = codename.split(".", 1)[0]
    else:
        resource_type = codename
    return (f"Permission {codename}", resource_type)


def _role_description(role_name: str) -> str:
    return ROLE_DESCRIPTIONS.get(role_name, f"Role {role_name}")


async def seed_roles_and_permissions(
    db: AsyncSession,
    model: PackAuthModel | None = None,
) -> None:
    """Seed permissions and roles defined by the active pack model.

    Idempotent — existing permissions/roles are not duplicated. Runtime CRUD
    via the /auth/roles and /auth/permissions endpoints continues to work on
    top of the seeded baseline.
    """
    pack_model = model if model is not None else load_active_model(settings.pack)

    # Seed permissions
    for codename in pack_model.permissions:
        existing = await db.execute(select(Permission).where(Permission.codename == codename))
        if existing.scalar_one_or_none():
            continue
        description, resource_type = _permission_meta(codename)
        db.add(Permission(codename=codename, description=description, resource_type=resource_type))
    await db.commit()

    # Load all permissions for role assignment
    result = await db.execute(select(Permission))
    all_perms = {p.codename: p for p in result.scalars().all()}

    # Seed roles
    for role_name in pack_model.roles:
        existing = await db.execute(
            select(DbRole).where(DbRole.name == role_name, DbRole.is_system == 1)
        )
        role = existing.scalar_one_or_none()
        if not role:
            role = DbRole(
                name=role_name,
                description=_role_description(role_name),
                is_system=True,
                is_default=(role_name == "pending"),
                created_at=datetime.now(UTC),
            )
            db.add(role)
            await db.commit()
            await db.refresh(role)

        # Assign permissions to role
        perm_codes = pack_model.permissions_for_role(role_name)

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
            DbRole.is_system == 1,
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
