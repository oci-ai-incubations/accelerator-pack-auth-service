import asyncio
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings


def _build_engine():
    """Build the async engine based on config.

    For Oracle 26ai: uses oracledb with the connection string passed as DSN.
    For PostgreSQL/SQLite: uses the database_url directly.
    """
    db_type = settings.database_type

    # Auto-detect from env vars
    if db_type == "auto":
        if settings.oracle_connection_string:
            db_type = "oracle"
        elif "postgresql" in settings.database_url:
            db_type = "postgres"
        else:
            db_type = "sqlite"

    if db_type == "oracle":
        # oracledb async requires oracle+oracledb:// with DSN in connect_args
        return create_async_engine(
            "oracle+oracledb://",
            thick_mode=False,
            connect_args={
                "user": settings.oracle_user,
                "password": settings.oracle_password,
                "dsn": settings.oracle_connection_string,
            },
            pool_size=5,
            max_overflow=10,
            echo=False,
        )
    elif db_type == "postgres":
        return create_async_engine(
            settings.database_url,
            pool_size=5,
            max_overflow=10,
            echo=False,
        )
    else:
        # SQLite
        return create_async_engine(settings.database_url, echo=False)


engine = _build_engine()
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _run_alembic_upgrade() -> None:
    """Synchronous: run `alembic upgrade head` against the runtime DB.

    alembic/env.py reads settings directly so the upgrade targets whatever
    database the app is configured for (sqlite / postgres / oracle).
    """
    from alembic import command
    from alembic.config import Config

    # Resolve alembic.ini + alembic/ via two candidate roots:
    #   - Path.cwd(): correct in the container (Dockerfile sets WORKDIR
    #     and ships alembic.ini + alembic/ there).
    #   - parents[2] of this module: correct in dev/test source layout
    #     (src/accelerator_pack_auth_service/ → repo root).
    # When the package is pip-installed (site-packages), parents[2] resolves
    # to <python-prefix>/, which lacks alembic/. cwd is the reliable handle.
    candidates = [Path.cwd(), Path(__file__).resolve().parents[2]]
    repo_root = next((p for p in candidates if (p / "alembic.ini").exists()), candidates[0])
    ini_path = repo_root / "alembic.ini"
    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    command.upgrade(cfg, "head")


async def init_db() -> None:
    """Run database migrations to ensure schema is current.

    Replaces the previous `Base.metadata.create_all` so existing tables get
    ALTERed by migrations instead of silently kept on a stale schema.

    alembic env.py uses `asyncio.run()` internally, which can't be invoked
    from inside an active event loop. Dispatch the synchronous alembic call
    to a worker thread.
    """
    await asyncio.to_thread(_run_alembic_upgrade)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
