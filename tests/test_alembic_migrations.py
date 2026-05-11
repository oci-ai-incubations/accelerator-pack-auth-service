"""Verifies alembic migrations honor runtime settings and produce expected tables."""

import os
import tempfile

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
async def test_alembic_upgrade_head_creates_users_table_on_sqlite(monkeypatch):
    """`init_db` runs alembic upgrade head against the configured SQLite DB
    and produces a users table with an auto-generated id column."""
    # Use a temp SQLite file (in-memory doesn't survive the alembic engine's
    # connect/dispose cycle since each connect gets a fresh database).
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        url = f"sqlite+aiosqlite:///{path}"
        monkeypatch.setenv("AUTH_DATABASE_URL", url)
        monkeypatch.setenv("AUTH_DATABASE_TYPE", "sqlite")
        # Reload settings + database module so the new URL is picked up.
        from importlib import reload

        import accelerator_pack_auth_service.config as config_mod
        import accelerator_pack_auth_service.database as database_mod

        reload(config_mod)
        reload(database_mod)

        await database_mod.init_db()

        # Verify users table was created with the expected columns.
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
            cols = await conn.run_sync(lambda c: inspect(c).get_columns("users"))
        await engine.dispose()

        assert "users" in tables, f"users table missing; got {sorted(tables)}"
        col_names = {c["name"] for c in cols}
        assert {"id", "email", "name", "password_hash"}.issubset(col_names), (
            f"expected core columns; got {sorted(col_names)}"
        )
        # id column is primary key + auto-increment / identity
        id_col = next(c for c in cols if c["name"] == "id")
        assert id_col["primary_key"], "id should be primary key"
    finally:
        if os.path.exists(path):
            os.unlink(path)


@pytest.mark.asyncio
async def test_alembic_upgrade_idempotent_on_second_run(monkeypatch):
    """Running migrations twice should be a no-op once head is reached."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        url = f"sqlite+aiosqlite:///{path}"
        monkeypatch.setenv("AUTH_DATABASE_URL", url)
        monkeypatch.setenv("AUTH_DATABASE_TYPE", "sqlite")
        from importlib import reload

        import accelerator_pack_auth_service.config as config_mod
        import accelerator_pack_auth_service.database as database_mod

        reload(config_mod)
        reload(database_mod)

        await database_mod.init_db()
        await database_mod.init_db()  # should not raise
    finally:
        if os.path.exists(path):
            os.unlink(path)
