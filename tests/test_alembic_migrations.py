"""Verifies alembic migrations against a local SQLite engine.

These tests use pytest's `tmp_path` fixture for an isolated SQLite file and
inject the URL into alembic via `cfg.set_main_option(...)`. They DO NOT
mutate the auth-service's module-level engine or settings; running them
should not affect any other test's view of `database.engine` / `config.settings`.
"""

import asyncio
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine


def _alembic_config_for(url: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


async def _table_inspect(url: str):
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
            cols = await conn.run_sync(
                lambda c: inspect(c).get_columns("users") if "users" in tables else []
            )
        return tables, cols
    finally:
        await engine.dispose()


def test_alembic_upgrade_head_creates_users_table_on_sqlite(tmp_path: Path) -> None:
    """alembic upgrade head against a fresh SQLite produces the users table."""
    db_file = tmp_path / "alembic_test.db"
    url = f"sqlite+aiosqlite:///{db_file}"

    command.upgrade(_alembic_config_for(url), "head")

    tables, cols = asyncio.run(_table_inspect(url))
    assert "users" in tables, f"users table missing; got {sorted(tables)}"
    col_names = {c["name"] for c in cols}
    assert {"id", "email", "name", "password_hash"}.issubset(col_names), (
        f"expected core columns; got {sorted(col_names)}"
    )
    id_col = next(c for c in cols if c["name"] == "id")
    assert id_col["primary_key"], "id should be primary key"


def test_alembic_upgrade_idempotent_on_second_run(tmp_path: Path) -> None:
    """Running upgrade head twice is a no-op once head is reached."""
    db_file = tmp_path / "alembic_idempotent.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    cfg = _alembic_config_for(url)

    command.upgrade(cfg, "head")
    # Second invocation should not raise.
    command.upgrade(cfg, "head")


@pytest.mark.parametrize(
    "revision", ["001", "002", "003", "004", "005", "006", "007", "008", "009", "010", "011"]
)
def test_alembic_step_upgrades(tmp_path: Path, revision: str) -> None:
    """Each intermediate revision can be reached without error."""
    db_file = tmp_path / f"alembic_step_{revision}.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    command.upgrade(_alembic_config_for(url), revision)


def test_alembic_head_creates_sso_state_table(tmp_path: Path) -> None:
    """Migration 011 adds the sso_state table for SSO CSRF / nonce defense."""
    db_file = tmp_path / "alembic_sso_state.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    command.upgrade(_alembic_config_for(url), "head")

    tables, _ = asyncio.run(_table_inspect(url))
    assert "sso_state" in tables
