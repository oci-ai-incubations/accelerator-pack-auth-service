from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base


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


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
