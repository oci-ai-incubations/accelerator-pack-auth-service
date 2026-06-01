"""cuopt pack — vehicle routing problem (VRP) RBAC.

Three roles: admin (everything), user (solve + view + chat + weather),
reader (view-only). No collection-style fine-grained perms; cuopt has no
per-tenant resources.
"""

from .base import PERMISSION_WILDCARD, PackAuthModel

CUOPT_MODEL = PackAuthModel(
    pack_id="cuopt",
    roles=["admin", "user", "reader"],
    permissions=[
        # routing core
        "cuopt.solve",
        "cuopt.view",
        # optional features (admin-gated via feature flags)
        "chat.use",
        "weather.view",
        "config.read",
        # admin
        "admin.users.manage",
        "admin.config.write",
        "admin.features.toggle",
        "admin.audit.view",
    ],
    role_permissions={
        "admin": [PERMISSION_WILDCARD],
        "user": [
            "cuopt.solve",
            "cuopt.view",
            "chat.use",
            "weather.view",
            "config.read",
        ],
        "reader": ["cuopt.view", "config.read"],
    },
)
