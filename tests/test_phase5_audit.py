"""Tests for Phase 5: audit logging, query, export, purge."""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from accelerator_pack_auth_service.models import Base

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


async def _get_admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return resp.json()["access_token"]


# ── Audit Service Unit Tests ─────────────────────


@pytest_asyncio.fixture
async def audit_db():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_log_event(audit_db: AsyncSession):
    from accelerator_pack_auth_service.audit_service import log_event

    entry = await log_event(
        audit_db,
        "user.login",
        actor_user_id=1,
        actor_email="test@test.com",
        ip_address="127.0.0.1",
        details={"method": "password"},
    )
    assert entry is not None
    assert entry.event_type == "user.login"
    assert entry.actor_email == "test@test.com"


@pytest.mark.asyncio
async def test_query_audit_logs_with_filters(audit_db: AsyncSession):
    from accelerator_pack_auth_service.audit_service import log_event, query_audit_logs

    await log_event(audit_db, "user.login", actor_user_id=1)
    await log_event(audit_db, "user.login", actor_user_id=2)
    await log_event(audit_db, "user.logout", actor_user_id=1)

    # Filter by event_type
    logs, total = await query_audit_logs(audit_db, event_type="user.login")
    assert total == 2

    # Filter by actor
    logs, total = await query_audit_logs(audit_db, actor_user_id=1)
    assert total == 2


@pytest.mark.asyncio
async def test_query_audit_logs_pagination(audit_db: AsyncSession):
    from accelerator_pack_auth_service.audit_service import log_event, query_audit_logs

    for i in range(10):
        await log_event(audit_db, "test.event", actor_user_id=i)

    logs, total = await query_audit_logs(audit_db, offset=0, limit=3)
    assert total == 10
    assert len(logs) == 3

    logs2, _ = await query_audit_logs(audit_db, offset=3, limit=3)
    assert len(logs2) == 3
    # Different entries
    assert logs[0].id != logs2[0].id


@pytest.mark.asyncio
async def test_audit_log_to_dict(audit_db: AsyncSession):
    from accelerator_pack_auth_service.audit_service import audit_log_to_dict, log_event

    entry = await log_event(
        audit_db,
        "role.assigned",
        actor_user_id=1,
        target_type="user",
        target_id="42",
    )
    d = audit_log_to_dict(entry)
    assert d["event_type"] == "role.assigned"
    assert d["target_type"] == "user"
    assert d["target_id"] == "42"
    assert "timestamp" in d


@pytest.mark.asyncio
async def test_purge_old_logs(audit_db: AsyncSession):
    from datetime import UTC, datetime, timedelta

    from accelerator_pack_auth_service.audit_service import purge_old_logs
    from accelerator_pack_auth_service.models import AuditLog, AuditResult

    # Insert an old entry directly
    old = AuditLog(
        timestamp=datetime.now(UTC) - timedelta(days=200),
        event_type="old.event",
        result=AuditResult.success,
        created_at=datetime.now(UTC) - timedelta(days=200),
    )
    audit_db.add(old)
    await audit_db.commit()

    # Insert a recent entry
    recent = AuditLog(
        timestamp=datetime.now(UTC),
        event_type="recent.event",
        result=AuditResult.success,
        created_at=datetime.now(UTC),
    )
    audit_db.add(recent)
    await audit_db.commit()

    deleted = await purge_old_logs(audit_db)
    assert deleted == 1  # Only old entry purged


# ── Audit Endpoint Tests ─────────────────────────


@pytest.mark.asyncio
async def test_audit_query_endpoint(client: AsyncClient):
    """Admin can query audit logs via GET /auth/audit."""
    token = await _get_admin_token(client)

    # Actions during registration create audit entries indirectly
    resp = await client.get("/auth/audit", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_audit_query_with_params(client: AsyncClient):
    token = await _get_admin_token(client)

    resp = await client.get(
        "/auth/audit?limit=5&offset=0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["limit"] == 5
    assert resp.json()["offset"] == 0


@pytest.mark.asyncio
async def test_audit_export_endpoint(client: AsyncClient):
    token = await _get_admin_token(client)

    resp = await client.get("/auth/audit/export", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_audit_purge_endpoint(client: AsyncClient):
    token = await _get_admin_token(client)

    resp = await client.post("/auth/audit/purge", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "deleted" in resp.json()


@pytest.mark.asyncio
async def test_non_admin_cannot_query_audit(client: AsyncClient):
    await _get_admin_token(client)  # Ensure admin exists first
    # Register a non-admin user
    user = await client.post(
        "/auth/register",
        json={"email": "nonadmin@test.com", "password": "password123", "name": "User"},
    )
    user_token = user.json()["access_token"]

    resp = await client.get("/auth/audit", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403
