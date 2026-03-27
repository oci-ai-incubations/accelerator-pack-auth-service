import asyncio
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from models import Base

# Use in-memory SQLite for tests
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

os.environ["AUTH_DATABASE_URL"] = TEST_DB_URL
os.environ["AUTH_JWT_SECRET"] = "test-secret"
os.environ["AUTH_RATE_LIMIT_LOGIN"] = "1000/minute"
os.environ["AUTH_RATE_LIMIT_REGISTER"] = "1000/minute"
os.environ["AUTH_ACCOUNT_LOCKOUT_THRESHOLD"] = "3"
os.environ["AUTH_ACCOUNT_LOCKOUT_DURATION_MINUTES"] = "30"
os.environ["AUTH_MAX_CONCURRENT_SESSIONS"] = "5"


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
    from database import get_db

    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    from main import app

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
