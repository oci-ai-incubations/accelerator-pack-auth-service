"""Unit tests for the pure scope-resolution + scope-grant helpers."""

import json

import pytest

from accelerator_pack_auth_service.models import Role, ServiceAccount, User
from accelerator_pack_auth_service.pack_models import load_active_model
from accelerator_pack_auth_service.scopes import (
    InvalidScopeError,
    grant_scopes,
    parse_scope_string,
    resolve_principal_scopes,
)

# ── parse_scope_string ──────────────────────────────


def test_parse_scope_string_empty_returns_empty_list():
    assert parse_scope_string("") == []
    assert parse_scope_string(None) == []
    assert parse_scope_string("   ") == []


def test_parse_scope_string_single_value():
    assert parse_scope_string("cuopt.solve") == ["cuopt.solve"]


def test_parse_scope_string_multiple_values_space_separated():
    assert parse_scope_string("cuopt.solve cuopt.view") == ["cuopt.solve", "cuopt.view"]


def test_parse_scope_string_collapses_whitespace_runs():
    assert parse_scope_string("cuopt.solve    cuopt.view\tchat.use") == [
        "cuopt.solve",
        "cuopt.view",
        "chat.use",
    ]


def test_parse_scope_string_preserves_order():
    assert parse_scope_string("c b a") == ["c", "b", "a"]


# ── resolve_principal_scopes (User) ─────────────────


def _user(role: Role, allowed_scopes: str | None = None) -> User:
    u = User()
    u.id = 1
    u.email = "u@example.com"
    u.name = "U"
    u.role = role
    u.is_active = True
    u.allowed_scopes = allowed_scopes
    return u


def test_resolve_user_role_expansion_for_admin_returns_all_cuopt_perms():
    model = load_active_model("cuopt")
    scopes = resolve_principal_scopes(_user(Role.admin), model)
    # Admin role is wildcard — expansion yields every codename the pack
    # declares, not the literal "*". Verifiers shouldn't need wildcard logic.
    assert set(scopes) == set(model.permissions)


def test_resolve_user_role_expansion_for_user_returns_user_perms():
    model = load_active_model("cuopt")
    scopes = resolve_principal_scopes(_user(Role.user), model)
    assert set(scopes) == {
        "cuopt.solve",
        "cuopt.view",
        "chat.use",
        "weather.view",
        "config.read",
    }


def test_resolve_user_role_expansion_for_reader_returns_reader_perms():
    model = load_active_model("cuopt")
    scopes = resolve_principal_scopes(_user(Role.reader), model)
    assert set(scopes) == {"cuopt.view", "config.read"}


def test_resolve_user_allowed_scopes_override_takes_precedence():
    model = load_active_model("cuopt")
    user = _user(Role.admin, allowed_scopes=json.dumps(["cuopt.view"]))
    # Even with the admin role's full expansion available, the explicit
    # override pins this user to the narrower default.
    assert resolve_principal_scopes(user, model) == ["cuopt.view"]


def test_resolve_user_allowed_scopes_corrupted_json_returns_empty():
    model = load_active_model("cuopt")
    user = _user(Role.admin, allowed_scopes="not-json")
    assert resolve_principal_scopes(user, model) == []


def test_resolve_user_allowed_scopes_non_list_returns_empty():
    model = load_active_model("cuopt")
    user = _user(Role.admin, allowed_scopes=json.dumps({"oops": "wrong-shape"}))
    assert resolve_principal_scopes(user, model) == []


def test_resolve_user_allowed_scopes_wildcard_expands_to_role_set_not_literal_star():
    """Spec 003 line 103: the literal "*" must never appear in a token's scope claim.

    A user stamped with ``allowed_scopes=["*"]`` expands to their role's
    full permission set so verifiers never need wildcard logic. The
    expansion goes to the role-set, NOT the pack's full permission set —
    a reader with allowed_scopes=["*"] still gets reader's perms, not admin's.
    """
    model = load_active_model("cuopt")
    user = _user(Role.reader, allowed_scopes=json.dumps(["*"]))
    scopes = resolve_principal_scopes(user, model)
    assert "*" not in scopes
    assert set(scopes) == set(model.permissions_for_role("reader"))


def test_resolve_user_allowed_scopes_wildcard_admin_expands_to_full_pack_vocabulary():
    """Admin's role is wildcard at the role level, so an admin with
    ``allowed_scopes=["*"]`` round-trips to every codename the pack declares."""
    model = load_active_model("cuopt")
    user = _user(Role.admin, allowed_scopes=json.dumps(["*"]))
    scopes = resolve_principal_scopes(user, model)
    assert "*" not in scopes
    assert set(scopes) == set(model.permissions)


# ── resolve_principal_scopes (ServiceAccount) ───────


def _client(scopes_json: str) -> ServiceAccount:
    sa = ServiceAccount()
    sa.id = 1
    sa.client_id = "cli_test"
    sa.scopes = scopes_json
    return sa


def test_resolve_service_account_reads_stamped_scopes():
    model = load_active_model("cuopt")
    sa = _client(json.dumps(["cuopt.solve"]))
    # The pack model is irrelevant for service accounts — scopes are stamped
    # at registration time and never role-expand.
    assert resolve_principal_scopes(sa, model) == ["cuopt.solve"]


def test_resolve_service_account_empty_scopes_returns_empty():
    model = load_active_model("cuopt")
    assert resolve_principal_scopes(_client(""), model) == []


def test_resolve_service_account_wildcard_expands_to_pack_vocabulary():
    """A service account stamped with ``["*"]`` carries the active pack's
    full permission set, never the literal ``*``."""
    model = load_active_model("cuopt")
    sa = _client(json.dumps(["*"]))
    scopes = resolve_principal_scopes(sa, model)
    assert "*" not in scopes
    assert set(scopes) == set(model.permissions)


# ── grant_scopes ────────────────────────────────────


def test_grant_no_requested_returns_full_allowed_set():
    allowed = ["cuopt.solve", "cuopt.view"]
    assert grant_scopes(allowed, None, strict=False) == ["cuopt.solve", "cuopt.view"]
    assert grant_scopes(allowed, [], strict=False) == ["cuopt.solve", "cuopt.view"]


def test_grant_subset_requested_returns_subset_in_allowed_order():
    allowed = ["cuopt.solve", "cuopt.view", "chat.use"]
    requested = ["chat.use", "cuopt.solve"]
    assert grant_scopes(allowed, requested, strict=False) == ["cuopt.solve", "chat.use"]


def test_grant_lenient_partial_overlap_returns_intersection():
    allowed = ["cuopt.solve"]
    requested = ["cuopt.solve", "admin.users.manage"]
    assert grant_scopes(allowed, requested, strict=False) == ["cuopt.solve"]


def test_grant_lenient_empty_intersection_raises_invalid_scope():
    # The error message lists the offending scope names — matches strict
    # mode's behavior so integrators get the same actionable detail
    # regardless of mode.
    with pytest.raises(InvalidScopeError, match="admin.users.manage"):
        grant_scopes(["cuopt.view"], ["admin.users.manage"], strict=False)


def test_grant_lenient_empty_intersection_message_lists_all_unallowed():
    with pytest.raises(InvalidScopeError, match="admin.users.manage other.bad"):
        grant_scopes(["cuopt.view"], ["admin.users.manage", "other.bad"], strict=False)


def test_grant_strict_partial_overlap_raises_with_missing_listed():
    with pytest.raises(InvalidScopeError, match="admin.users.manage"):
        grant_scopes(["cuopt.solve"], ["cuopt.solve", "admin.users.manage"], strict=True)


def test_grant_strict_full_overlap_succeeds():
    assert grant_scopes(["cuopt.solve"], ["cuopt.solve"], strict=True) == ["cuopt.solve"]


def test_grant_strict_no_request_returns_full_allowed_set():
    # Strict mode only fires when the request asks for *something*; empty
    # request is the "no scope requested" RFC path and is treated the same.
    assert grant_scopes(["cuopt.solve"], None, strict=True) == ["cuopt.solve"]
