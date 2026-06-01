"""vss pack — video search & summarization RBAC.

Three roles: admin (everything), user (full app — run summarization +
view + annotate), reader (view-only on completed summaries). The
``vss.review`` permission gates the row-level annotation edits on
``app/content-review`` so a "reader" cohort can browse without
mutating the dataset.

The vss-oci backend (NVIDIA blueprint fork) is reached via the
vss-oracle-ux Next.js server, never directly from the browser, so
backend-route scope checks aren't in scope here; protection happens at
the Next.js auth-aware fetch client and the ingress auth-url
annotation. See AUTH-INTEGRATION.md.

The ``admin.*`` permissions are listed so the vss-oracle-ux admin
panel's ``filterTabs`` check can introspect what the active deployment
supports via ``GET /auth/pack/model``. The ``admin`` role binds
``PERMISSION_WILDCARD`` and therefore inherits all of them at runtime.
"""

from .base import PERMISSION_WILDCARD, PackAuthModel

VSS_MODEL = PackAuthModel(
    pack_id="vss",
    roles=["admin", "user", "reader"],
    permissions=[
        # core summarization workflow
        "vss.summarize",
        "vss.view",
        "vss.review",
        # admin surface published to the FE for tab visibility
        "admin.users.manage",
        "admin.roles.manage",
        "admin.groups.manage",
        "admin.providers.manage",
        "admin.collections.manage",
        "admin.features.toggle",
        "admin.config.write",
        "admin.audit.view",
    ],
    role_permissions={
        "admin": [PERMISSION_WILDCARD],
        "user": [
            "vss.summarize",
            "vss.view",
            "vss.review",
        ],
        "reader": ["vss.view"],
    },
)
