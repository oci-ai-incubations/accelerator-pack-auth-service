"""Validity tests for each pack auth model."""

import pytest

from accelerator_pack_auth_service.pack_models import (
    BASE_MODEL,
    CUOPT_MODEL,
    DOX_PACK_MODEL,
    PAAS_RAG_MODEL,
    PACK_MODELS,
    PERMISSION_WILDCARD,
    VSS_MODEL,
    WAREHOUSE_PICK_PATH_MODEL,
    PackAuthModel,
)


@pytest.mark.parametrize(
    "model",
    [
        BASE_MODEL,
        CUOPT_MODEL,
        DOX_PACK_MODEL,
        PAAS_RAG_MODEL,
        VSS_MODEL,
        WAREHOUSE_PICK_PATH_MODEL,
    ],
)
def test_model_consistency(model: PackAuthModel):
    """role_permissions must reference declared roles + permissions only."""
    for role in model.role_permissions:
        assert role in model.roles, f"{model.pack_id}: role_permissions has unknown role {role}"
    for role, perms in model.role_permissions.items():
        if PERMISSION_WILDCARD in perms:
            continue
        unknown = [p for p in perms if p not in model.permissions]
        assert not unknown, f"{model.pack_id}/{role}: unknown perms {unknown}"


def test_wildcard_expands_to_all_permissions():
    assert sorted(CUOPT_MODEL.permissions_for_role("admin")) == sorted(CUOPT_MODEL.permissions)


def test_cuopt_user_subset_of_permissions():
    user_perms = CUOPT_MODEL.permissions_for_role("user")
    assert "cuopt.solve" in user_perms
    assert "cuopt.view" in user_perms
    assert "admin.users.manage" not in user_perms


def test_cuopt_reader_is_view_only():
    reader_perms = CUOPT_MODEL.permissions_for_role("reader")
    assert "cuopt.view" in reader_perms
    assert "cuopt.solve" not in reader_perms
    assert "admin.users.manage" not in reader_perms


def test_unknown_role_returns_empty():
    assert CUOPT_MODEL.permissions_for_role("nobody") == []


def test_is_valid_role_and_permission():
    assert CUOPT_MODEL.is_valid_role("admin") is True
    assert CUOPT_MODEL.is_valid_role("nobody") is False
    assert CUOPT_MODEL.is_valid_permission("cuopt.solve") is True
    assert CUOPT_MODEL.is_valid_permission("nope") is False


def test_paas_rag_collections_perms_present():
    """paas_rag retains the historical collection-based permission set."""
    assert "collections:read" in PAAS_RAG_MODEL.permissions
    assert "collections:write" in PAAS_RAG_MODEL.permissions
    user_perms = PAAS_RAG_MODEL.permissions_for_role("user")
    assert "collections:read" in user_perms
    assert "collections:write" in user_perms


def test_base_model_is_minimal():
    assert BASE_MODEL.roles == ["admin", "user"]
    assert BASE_MODEL.permissions_for_role("user") == []


def test_invalid_model_rejected():
    """role_permissions referencing an unknown role/permission is rejected."""
    with pytest.raises(ValueError, match="unknown role"):
        PackAuthModel(
            pack_id="bad",
            roles=["admin"],
            permissions=["x"],
            role_permissions={"missing": ["x"]},
        )
    with pytest.raises(ValueError, match="unknown permissions"):
        PackAuthModel(
            pack_id="bad",
            roles=["admin"],
            permissions=["x"],
            role_permissions={"admin": ["x", "y"]},
        )


def test_registry_contains_all_named_models():
    expected = {
        "base",
        "cuopt",
        "paas_rag",
        "vss",
        "warehouse_pick_path",
        "dox_pack",
    }
    assert expected.issubset(PACK_MODELS.keys())
