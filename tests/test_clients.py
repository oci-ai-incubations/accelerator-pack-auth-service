"""Unit tests for the OAuth2 service-account helpers in ``clients.py``.

Mirrors the test surface of ``auth.py`` — pure-function credential helpers
plus CRUD-flow tests through a real async session. The conftest's session
fixture yields a fresh in-memory SQLite per test, so each test starts clean.
"""

from datetime import UTC, datetime, timedelta

import pytest

from accelerator_pack_auth_service import clients
from accelerator_pack_auth_service.models import Role, ServiceAccount, User


def test_generate_client_id_has_prefix_and_length():
    client_id = clients.generate_client_id()
    assert client_id.startswith("cli_")
    # token_urlsafe(16) emits 22 chars; total = 4 + 22 = 26.
    assert len(client_id) == len(clients.CLIENT_ID_PREFIX) + 22


def test_generate_client_secret_has_prefix_and_length():
    secret = clients.generate_client_secret()
    assert secret.startswith("csk_")
    # token_urlsafe(32) emits 43 chars.
    assert len(secret) == len(clients.CLIENT_SECRET_PREFIX) + 43


def test_generate_client_id_unique_across_calls():
    seen = {clients.generate_client_id() for _ in range(64)}
    assert len(seen) == 64


def test_generate_client_secret_unique_across_calls():
    seen = {clients.generate_client_secret() for _ in range(64)}
    assert len(seen) == 64


def test_hash_secret_then_verify_roundtrip():
    plaintext = clients.generate_client_secret()
    hashed = clients.hash_secret(plaintext)
    assert hashed != plaintext  # never store plaintext
    assert clients.verify_secret(plaintext, hashed)


def test_verify_secret_rejects_wrong_plaintext():
    hashed = clients.hash_secret(clients.generate_client_secret())
    assert not clients.verify_secret("csk_wrong-value", hashed)


def test_verify_secret_returns_false_on_malformed_hash():
    # Truncated / corrupt hash on disk must never raise — we always want a
    # boolean so the token endpoint can map both cases to invalid_client.
    assert not clients.verify_secret("anything", "not-a-bcrypt-hash")


def test_serialize_deserialize_scopes_roundtrip():
    raw = clients._serialize_scopes(["cuopt.solve", "cuopt.view"])  # noqa: SLF001
    assert clients.deserialize_scopes(raw) == ["cuopt.solve", "cuopt.view"]


def test_deserialize_scopes_handles_empty_and_invalid():
    assert clients.deserialize_scopes(None) == []
    assert clients.deserialize_scopes("") == []
    assert clients.deserialize_scopes("not-json") == []
    assert clients.deserialize_scopes('{"not": "a list"}') == []


def test_is_client_usable_active_default(_=None):
    account = ServiceAccount(
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes="[]",
        owner_user_id=1,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    assert clients.is_client_usable(account)


def test_is_client_usable_inactive_false():
    account = ServiceAccount(
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes="[]",
        owner_user_id=1,
        is_active=False,
        created_at=datetime.now(UTC),
    )
    assert not clients.is_client_usable(account)


def test_is_client_usable_revoked_false():
    account = ServiceAccount(
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes="[]",
        owner_user_id=1,
        is_active=True,
        revoked_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )
    assert not clients.is_client_usable(account)


def test_is_client_usable_expired_false():
    account = ServiceAccount(
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes="[]",
        owner_user_id=1,
        is_active=True,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
        created_at=datetime.now(UTC),
    )
    assert not clients.is_client_usable(account)


def test_is_client_usable_naive_expires_at_treated_as_utc():
    # Some DBs strip tzinfo on round-trip; the helper must still compare
    # safely against a tz-aware ``now``.
    account = ServiceAccount(
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes="[]",
        owner_user_id=1,
        is_active=True,
        expires_at=datetime(2000, 1, 1, 0, 0, 0),
        created_at=datetime.now(UTC),
    )
    assert not clients.is_client_usable(account)


def test_service_account_to_dict_omits_secret_by_default():
    account = ServiceAccount(
        id=1,
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes='["a", "b"]',
        owner_user_id=1,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    payload = clients.service_account_to_dict(account)
    assert "client_secret" not in payload
    assert payload["scopes"] == ["a", "b"]


def test_service_account_to_dict_includes_secret_when_plaintext_passed():
    account = ServiceAccount(
        id=1,
        client_id="cli_x",
        client_secret_hash="h",
        name="x",
        scopes="[]",
        owner_user_id=1,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    payload = clients.service_account_to_dict(account, plaintext="csk_one_time_value")
    assert payload["client_secret"] == "csk_one_time_value"


# ── Async CRUD against a real session ────────────


async def _seed_owner(db_session) -> User:
    owner = User(
        email="owner@example.com",
        name="Owner",
        password_hash="x",
        role=Role.admin,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    db_session.add(owner)
    await db_session.commit()
    await db_session.refresh(owner)
    return owner


@pytest.mark.asyncio
async def test_create_client_persists_hashed_secret_and_returns_plaintext(db_session):
    owner = await _seed_owner(db_session)
    account, plaintext = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="Fusion-ERP",
        description="prod",
        scopes=["cuopt.solve", "cuopt.view"],
        expires_at=None,
    )
    assert account.client_id.startswith("cli_")
    assert plaintext.startswith("csk_")
    assert account.client_secret_hash != plaintext
    fetched = await clients.get_client_by_client_id(db_session, account.client_id)
    assert fetched is not None
    assert clients.verify_secret(plaintext, fetched.client_secret_hash)


@pytest.mark.asyncio
async def test_rotate_secret_invalidates_old_secret(db_session):
    owner = await _seed_owner(db_session)
    account, original_plain = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=[],
        expires_at=None,
    )
    rotated = await clients.rotate_secret(db_session, account.id)
    assert rotated is not None
    rotated_account, new_plain = rotated
    assert new_plain != original_plain
    assert clients.verify_secret(new_plain, rotated_account.client_secret_hash)
    assert not clients.verify_secret(original_plain, rotated_account.client_secret_hash)


@pytest.mark.asyncio
async def test_rotate_secret_unknown_id_returns_none(db_session):
    assert await clients.rotate_secret(db_session, 99999) is None


@pytest.mark.asyncio
async def test_revoke_client_soft_deletes(db_session):
    owner = await _seed_owner(db_session)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=[],
        expires_at=None,
    )
    revoked = await clients.revoke_client(db_session, account.id)
    assert revoked is not None
    assert revoked.is_active is False
    assert revoked.revoked_at is not None


@pytest.mark.asyncio
async def test_revoke_client_unknown_id_returns_none(db_session):
    assert await clients.revoke_client(db_session, 99999) is None


@pytest.mark.asyncio
async def test_update_client_patches_fields(db_session):
    owner = await _seed_owner(db_session)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="initial",
        description=None,
        scopes=["a"],
        expires_at=None,
    )
    updated = await clients.update_client(
        db_session,
        account.id,
        name="renamed",
        scopes=["a", "b"],
    )
    assert updated is not None
    assert updated.name == "renamed"
    assert clients.deserialize_scopes(updated.scopes) == ["a", "b"]


@pytest.mark.asyncio
async def test_update_client_setting_inactive_stamps_revoked_at(db_session):
    owner = await _seed_owner(db_session)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=[],
        expires_at=None,
    )
    updated = await clients.update_client(db_session, account.id, is_active=False)
    assert updated is not None
    assert updated.is_active is False
    assert updated.revoked_at is not None


@pytest.mark.asyncio
async def test_update_client_can_clear_description(db_session):
    """Passing description=None must clear the column (B3 fix).

    Without the _UNSET sentinel, ``None`` was indistinguishable from "field
    omitted" so admins had no way to wipe a description once set.
    """
    owner = await _seed_owner(db_session)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description="initial description",
        scopes=[],
        expires_at=None,
    )
    cleared = await clients.update_client(db_session, account.id, description=None)
    assert cleared is not None
    assert cleared.description is None


@pytest.mark.asyncio
async def test_update_client_can_clear_expires_at(db_session):
    """Passing expires_at=None must clear the column (B3 fix)."""
    owner = await _seed_owner(db_session)
    future = datetime.now(UTC) + timedelta(days=30)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=[],
        expires_at=future,
    )
    cleared = await clients.update_client(db_session, account.id, expires_at=None)
    assert cleared is not None
    assert cleared.expires_at is None


@pytest.mark.asyncio
async def test_update_client_omitting_description_leaves_it_unchanged(db_session):
    """Omitting description (sentinel default) must not touch the column (B3 fix)."""
    owner = await _seed_owner(db_session)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description="keep me",
        scopes=[],
        expires_at=None,
    )
    updated = await clients.update_client(db_session, account.id, name="renamed")
    assert updated is not None
    assert updated.name == "renamed"
    assert updated.description == "keep me"


@pytest.mark.asyncio
async def test_update_client_unknown_id_returns_none(db_session):
    assert await clients.update_client(db_session, 99999, name="x") is None


@pytest.mark.asyncio
async def test_list_clients_for_owner_filters_by_owner(db_session):
    owner_a = await _seed_owner(db_session)
    owner_b = User(
        email="b@example.com",
        name="B",
        password_hash="x",
        role=Role.admin,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    db_session.add(owner_b)
    await db_session.commit()
    await db_session.refresh(owner_b)
    await clients.create_client(
        db_session,
        owner_id=owner_a.id,
        name="a-1",
        description=None,
        scopes=[],
        expires_at=None,
    )
    await clients.create_client(
        db_session,
        owner_id=owner_b.id,
        name="b-1",
        description=None,
        scopes=[],
        expires_at=None,
    )  # _plaintext discarded — only persistence matters here.
    assert len(await clients.list_clients_for_owner(db_session, owner_a.id)) == 1
    assert len(await clients.list_clients_for_owner(db_session, owner_b.id)) == 1
    assert len(await clients.list_all_clients(db_session)) == 2


@pytest.mark.asyncio
async def test_count_clients_for_owner_counts_active_and_revoked(db_session):
    owner = await _seed_owner(db_session)
    assert await clients.count_clients_for_owner(db_session, owner.id) == 0
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=[],
        expires_at=None,
    )
    await clients.revoke_client(db_session, account.id)
    # Revoked rows still count toward the cap.
    assert await clients.count_clients_for_owner(db_session, owner.id) == 1


@pytest.mark.asyncio
async def test_update_last_used_touches_metadata(db_session):
    owner = await _seed_owner(db_session)
    account, _ = await clients.create_client(
        db_session,
        owner_id=owner.id,
        name="x",
        description=None,
        scopes=[],
        expires_at=None,
    )
    await clients.update_last_used(db_session, account.client_id, "10.0.0.1")
    fetched = await clients.get_client_by_client_id(db_session, account.client_id)
    assert fetched is not None
    assert fetched.last_used_at is not None
    assert fetched.last_used_ip == "10.0.0.1"


@pytest.mark.asyncio
async def test_update_last_used_unknown_client_is_noop(db_session):
    # Returns None and writes nothing — never raises.
    await clients.update_last_used(db_session, "cli_does_not_exist", "10.0.0.1")
