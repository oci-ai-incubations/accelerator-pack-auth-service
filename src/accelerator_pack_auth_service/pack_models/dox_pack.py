"""dox_pack pack — stub. Same shape as BASE_MODEL."""

from .base import PERMISSION_WILDCARD, PackAuthModel

DOX_PACK_MODEL = PackAuthModel(
    pack_id="dox_pack",
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
