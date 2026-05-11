"""paas_rag pack — collection-based RBAC.

Mirrors the historical SYSTEM_ROLES + SYSTEM_PERMISSIONS in permission_service.py
so existing deploys are unchanged when AUTH_PACK=paas_rag.
"""

from .base import PERMISSION_WILDCARD, PackAuthModel

PAAS_RAG_MODEL = PackAuthModel(
    pack_id="paas_rag",
    roles=["admin", "user", "reader", "pending"],
    permissions=[
        "users:list",
        "users:read",
        "users:update",
        "users:delete",
        "collections:read",
        "collections:write",
        "collections:manage",
        "collections:delete",
        "roles:list",
        "roles:create",
        "roles:read",
        "roles:update",
        "roles:delete",
        "permissions:list",
        "permissions:check",
    ],
    role_permissions={
        "admin": [PERMISSION_WILDCARD],
        "user": ["collections:read", "collections:write"],
        "reader": ["collections:read"],
        "pending": [],
    },
)
