"""Active-model loader tests."""

import logging

from accelerator_pack_auth_service.pack_models import (
    BASE_MODEL,
    CUOPT_MODEL,
    PAAS_RAG_MODEL,
    load_active_model,
)


def test_load_known_pack():
    assert load_active_model("cuopt") is CUOPT_MODEL
    assert load_active_model("paas_rag") is PAAS_RAG_MODEL


def test_load_unknown_pack_falls_back_to_base(caplog):
    with caplog.at_level(logging.WARNING):
        model = load_active_model("not-a-real-pack")
    assert model is BASE_MODEL
    assert any("not-a-real-pack" in r.message for r in caplog.records)


def test_load_base_explicitly():
    assert load_active_model("base") is BASE_MODEL
