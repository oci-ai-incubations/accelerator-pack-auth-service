"""Registry of all known pack auth models + active-model loader."""

import logging

from .base import BASE_MODEL, PackAuthModel
from .cuopt import CUOPT_MODEL
from .dox_pack import DOX_PACK_MODEL
from .paas_rag import PAAS_RAG_MODEL
from .vss import VSS_MODEL
from .warehouse_pick_path import WAREHOUSE_PICK_PATH_MODEL

logger = logging.getLogger(__name__)

PACK_MODELS: dict[str, PackAuthModel] = {
    "base": BASE_MODEL,
    "cuopt": CUOPT_MODEL,
    "paas_rag": PAAS_RAG_MODEL,
    "vss": VSS_MODEL,
    "warehouse_pick_path": WAREHOUSE_PICK_PATH_MODEL,
    "dox_pack": DOX_PACK_MODEL,
}


def load_active_model(pack_id: str) -> PackAuthModel:
    """Return the pack model for `pack_id`, or BASE_MODEL with a warning if unknown."""
    model = PACK_MODELS.get(pack_id)
    if model is None:
        logger.warning(
            "Unknown AUTH_PACK=%r; falling back to BASE_MODEL. Known packs: %s",
            pack_id,
            sorted(PACK_MODELS.keys()),
        )
        return BASE_MODEL
    return model
