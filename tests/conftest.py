import asyncio
import os

# Use in-memory SQLite for tests. Env vars must be set BEFORE any
# accelerator_pack_auth_service.* module is imported below, because the
# settings singleton is built on first import.
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

os.environ["AUTH_DATABASE_URL"] = TEST_DB_URL
os.environ["AUTH_JWT_SECRET"] = "test-secret"
os.environ["AUTH_RATE_LIMIT_LOGIN"] = "1000/minute"
os.environ["AUTH_RATE_LIMIT_REGISTER"] = "1000/minute"
os.environ["AUTH_ACCOUNT_LOCKOUT_THRESHOLD"] = "3"
os.environ["AUTH_ACCOUNT_LOCKOUT_DURATION_MINUTES"] = "30"
os.environ["AUTH_MAX_CONCURRENT_SESSIONS"] = "5"
os.environ["AUTH_SCIM_ENABLED"] = "true"
# SHA256 hash of "test-scim-token"
os.environ["AUTH_SCIM_TOKEN"] = "96d72274517e0d926344cee50c7da354c52ccf06fb22fc45a34958db62a84d4f"
# Default test pack: paas_rag-style RBAC (collections-based perms). Individual
# tests can monkeypatch settings.pack for pack-specific scenarios.
os.environ["AUTH_PACK"] = "paas_rag"

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402

from accelerator_pack_auth_service.models import Base  # noqa: E402


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed system roles and permissions for RBAC tests
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        from accelerator_pack_auth_service.permission_service import seed_roles_and_permissions

        await seed_roles_and_permissions(session)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_engine):
    """Create a test client with a fresh database."""
    from accelerator_pack_auth_service.database import get_db

    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    from accelerator_pack_auth_service.main import app

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
