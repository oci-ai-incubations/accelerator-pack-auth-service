"""Alembic environment.

Migrations honor the runtime application config (AUTH_DATABASE_TYPE +
AUTH_DATABASE_URL / AUTH_ORACLE_* env vars) rather than the static
sqlalchemy.url in alembic.ini. This keeps the migration target in lock-step
with what the running app talks to, so a deploy can't end up with an Alembic
SQLite schema and an Oracle runtime engine.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.models import Base

config = context.config
if config.config_file_name is not None:
    # disable_existing_loggers=False so importing alembic during tests
    # doesn't silence pre-existing loggers (e.g. pack_models.registry),
    # which would otherwise break caplog-based assertions later in the run.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _resolved_db_type() -> str:
    """Mirror database._build_engine's auto-detect logic."""
    db_type = settings.database_type
    if db_type == "auto":
        if settings.oracle_connection_string:
            return "oracle"
        if "postgresql" in settings.database_url:
            return "postgres"
        return "sqlite"
    return db_type


def _runtime_url_and_connect_args() -> tuple[str, dict]:
    """URL + connect_args that match database._build_engine()."""
    db_type = _resolved_db_type()
    if db_type == "oracle":
        return (
            "oracle+oracledb://",
            {
                "user": settings.oracle_user,
                "password": settings.oracle_password,
                "dsn": settings.oracle_connection_string,
            },
        )
    return (settings.database_url, {})


# Escape hatch for tests: if the caller has set a non-default URL via
# cfg.set_main_option("sqlalchemy.url", ...) BEFORE invoking alembic
# command.upgrade(), honor it. The default value in alembic.ini is treated
# as "no override" so production behavior remains settings-driven.
_INI_DEFAULT_URL = "sqlite+aiosqlite:///./auth.db"
_explicit_url = config.get_main_option("sqlalchemy.url")
if _explicit_url and _explicit_url != _INI_DEFAULT_URL:
    _runtime_url = _explicit_url
    _runtime_connect_args: dict = {}
else:
    _runtime_url, _runtime_connect_args = _runtime_url_and_connect_args()
    config.set_main_option("sqlalchemy.url", _runtime_url)


def run_migrations_offline() -> None:
    """Offline mode — emit SQL against the runtime URL."""
    context.configure(url=_runtime_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Online async mode — build a fresh async engine from runtime settings."""
    connectable = create_async_engine(
        _runtime_url,
        poolclass=pool.NullPool,
        connect_args=_runtime_connect_args,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
