"""warehouse_pick_path pack — stub. Same shape as BASE_MODEL."""

from .base import PERMISSION_WILDCARD, PackAuthModel

WAREHOUSE_PICK_PATH_MODEL = PackAuthModel(
    pack_id="warehouse_pick_path",
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
