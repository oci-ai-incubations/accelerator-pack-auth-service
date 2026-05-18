"""Unit tests for the pure scope-resolution + scope-grant helpers."""

import json

import pytest

from accelerator_pack_auth_service.models import (
    DbRole,
    Permission,
    Role,
    RolePermission,
    ServiceAccount,
    User,
    UserRole,
)
from accelerator_pack_auth_service.pack_models import load_active_model
from accelerator_pack_auth_service.scopes import (
    InvalidScopeError,
    fetch_user_role_permissions,
    grant_scopes,
    parse_scope_string,
    resolve_effective_user_scopes,
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


# ── fetch_user_role_permissions / resolve_effective_user_scopes ──


async def _seed_user_with_custom_role(
    session,
    *,
    email: str,
    primary_role: Role,
    role_name: str,
    permission_codenames: list[str],
    allowed_scopes: str | None = None,
) -> User:
    """Create a user + a custom DbRole with the given permissions, assigned via UserRole."""
    user = User(
        email=email,
        name=email.split("@")[0],
        password_hash="x",
        role=primary_role,
        allowed_scopes=allowed_scopes,
    )
    session.add(user)
    await session.flush()

    role = DbRole(name=role_name, description=f"custom {role_name}", is_system=False)
    session.add(role)
    await session.flush()

    for codename in permission_codenames:
        result = await session.execute(
            Permission.__table__.select().where(Permission.codename == codename)
        )
        row = result.first()
        if row is None:
            perm = Permission(codename=codename, description=codename)
            session.add(perm)
            await session.flush()
            perm_id = perm.id
        else:
            perm_id = row.id
        session.add(RolePermission(role_id=role.id, permission_id=perm_id))

    session.add(UserRole(user_id=user.id, role_id=role.id))
    await session.commit()
    return user


@pytest.mark.asyncio
async def test_resolve_effective_user_scopes_unions_user_role_permissions(db_session, monkeypatch):
    """Headline behavior: a Reader-primary user with a custom role that
    grants vss.summarize + vss.review gets all three scopes (base ∪ extra)."""
    from accelerator_pack_auth_service.config import settings

    monkeypatch.setattr(settings, "pack", "vss")
    model = load_active_model("vss")

    user = await _seed_user_with_custom_role(
        db_session,
        email="union@scopes.test",
        primary_role=Role.reader,
        role_name="analyst",
        permission_codenames=["vss.summarize", "vss.review"],
    )

    scopes = await resolve_effective_user_scopes(db_session, user, model)

    # Base prefix preserved (reader → ["vss.view"]), new extras appended in
    # sorted order so order is deterministic across calls.
    assert scopes == ["vss.view", "vss.review", "vss.summarize"]


@pytest.mark.asyncio
async def test_resolve_effective_user_scopes_allowed_scopes_override_skips_union(
    db_session, monkeypatch
):
    """A user with allowed_scopes set must NOT have UserRole permissions
    unioned in — allowed_scopes is a deliberate narrowing override."""
    from accelerator_pack_auth_service.config import settings

    monkeypatch.setattr(settings, "pack", "vss")
    model = load_active_model("vss")

    user = await _seed_user_with_custom_role(
        db_session,
        email="narrow@scopes.test",
        primary_role=Role.reader,
        role_name="would-grant-more",
        permission_codenames=["vss.summarize"],
        allowed_scopes=json.dumps(["vss.view"]),
    )

    scopes = await resolve_effective_user_scopes(db_session, user, model)

    # The override pins the scope set; the UserRole-granted vss.summarize is
    # NOT unioned in.
    assert scopes == ["vss.view"]


@pytest.mark.asyncio
async def test_fetch_user_role_permissions_dedupes_across_overlapping_roles(db_session):
    """When two DbRoles both grant the same permission, the helper returns
    it once. Pins the ``.distinct()`` claim in the docstring."""
    user = User(
        email="dedupe@scopes.test",
        name="dedupe",
        password_hash="x",
        role=Role.user,
    )
    db_session.add(user)
    await db_session.flush()

    perm = Permission(codename="vss.view", description="vss.view")
    db_session.add(perm)
    await db_session.flush()

    for role_name in ("role_a", "role_b"):
        role = DbRole(name=role_name, is_system=False)
        db_session.add(role)
        await db_session.flush()
        db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        db_session.add(UserRole(user_id=user.id, role_id=role.id))
    await db_session.commit()

    result = await fetch_user_role_permissions(db_session, user.id)
    assert result == {"vss.view"}


@pytest.mark.asyncio
async def test_resolve_effective_user_scopes_empty_user_roles_returns_base_unchanged(
    db_session, monkeypatch
):
    """Short-circuit at the empty-extra branch: a user with zero UserRole
    rows gets back exactly resolve_principal_scopes — no sort, no rewrap."""
    from accelerator_pack_auth_service.config import settings

    monkeypatch.setattr(settings, "pack", "vss")
    model = load_active_model("vss")

    user = User(
        email="bare@scopes.test",
        name="bare",
        password_hash="x",
        role=Role.user,
    )
    db_session.add(user)
    await db_session.commit()

    scopes = await resolve_effective_user_scopes(db_session, user, model)
    # vss "user" role expands to vss.summarize + vss.view + vss.review in
    # the pack-model-declared order. The empty-extra path must preserve it.
    assert scopes == ["vss.summarize", "vss.view", "vss.review"]
