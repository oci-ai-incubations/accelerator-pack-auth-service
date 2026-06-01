"""Pack-extensible RBAC models.

Each accelerator pack ships its own role + permission set as a `PackAuthModel`
instance. The active model is selected at startup via `AUTH_PACK` env var and
seeds the DB on first deploy. Runtime CRUD via /auth/roles + /auth/permissions
keeps working on top — the pack model just supplies the initial state.

Add a new pack by creating `pack_models/<pack>.py` with a module-level constant
of type `PackAuthModel`, then register it in `registry.py`.
"""

from .base import BASE_MODEL, PERMISSION_WILDCARD, PackAuthModel
from .cuopt import CUOPT_MODEL
from .dox_pack import DOX_PACK_MODEL
from .paas_rag import PAAS_RAG_MODEL
from .registry import PACK_MODELS, load_active_model
from .vss import VSS_MODEL
from .warehouse_pick_path import WAREHOUSE_PICK_PATH_MODEL

__all__ = [
    "BASE_MODEL",
    "CUOPT_MODEL",
    "DOX_PACK_MODEL",
    "PAAS_RAG_MODEL",
    "PACK_MODELS",
    "PERMISSION_WILDCARD",
    "PackAuthModel",
    "VSS_MODEL",
    "WAREHOUSE_PICK_PATH_MODEL",
    "load_active_model",
]
