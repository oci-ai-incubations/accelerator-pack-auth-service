"""vss pack — stub. Same shape as BASE_MODEL; fill in pack-specific perms later."""

from .base import PERMISSION_WILDCARD, PackAuthModel

VSS_MODEL = PackAuthModel(
    pack_id="vss",
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
