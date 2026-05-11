"""Base pack-auth contract.

Per-pack RBAC is expressed as a `PackAuthModel` — the roles a pack supports,
the permission keys it distinguishes, and the default role-to-permissions
mapping seeded at first deploy.
"""

from pydantic import BaseModel, model_validator

PERMISSION_WILDCARD = "*"


class PackAuthModel(BaseModel):
    """Per-pack RBAC contract.

    `role_permissions` values are either an explicit list of permission keys
    (each of which must appear in `permissions`) OR `[PERMISSION_WILDCARD]`
    which expands to all declared permissions for the pack.
    """

    pack_id: str
    roles: list[str]
    permissions: list[str]
    role_permissions: dict[str, list[str]]

    @model_validator(mode="after")
    def _validate_consistency(self) -> "PackAuthModel":
        """Validate role_permissions references known roles and permissions."""
        for role in self.role_permissions:
            if role not in self.roles:
                raise ValueError(
                    f"role_permissions references unknown role '{role}' "
                    f"(declared roles: {self.roles})"
                )
        for role, perms in self.role_permissions.items():
            if PERMISSION_WILDCARD in perms:
                continue
            unknown = [p for p in perms if p not in self.permissions]
            if unknown:
                raise ValueError(
                    f"role '{role}' references unknown permissions {unknown} "
                    f"(declared permissions: {self.permissions})"
                )
        return self

    def permissions_for_role(self, role: str) -> list[str]:
        """Resolve the permission list for a role, expanding wildcard."""
        perms = self.role_permissions.get(role, [])
        if PERMISSION_WILDCARD in perms:
            return list(self.permissions)
        return list(perms)

    def is_valid_role(self, role: str) -> bool:
        """True if `role` is one of this pack's declared roles."""
        return role in self.roles

    def is_valid_permission(self, perm: str) -> bool:
        """True if `perm` is one of this pack's declared permissions."""
        return perm in self.permissions


BASE_MODEL = PackAuthModel(
    pack_id="base",
    roles=["admin", "user"],
    permissions=[
        "admin.users.manage",
        "admin.audit.view",
    ],
    role_permissions={
        "admin": [PERMISSION_WILDCARD],
        "user": [],
    },
)
