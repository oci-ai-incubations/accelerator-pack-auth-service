"""Direct unit tests for sso_service to ensure coverage."""

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from models import Base, DbRole, ExternalIdentity, IdentityProvider, Role, User, UserRole

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    # Seed roles
    async with session_factory() as session:
        from permission_service import seed_roles_and_permissions

        await seed_roles_and_permissions(session)
    async with session_factory() as session:
        yield session
    await engine.dispose()


async def _create_provider(db: AsyncSession) -> IdentityProvider:
    from datetime import UTC, datetime

    provider = IdentityProvider(
        type="oidc",
        name="Test",
        slug="test-provider",
        config={},
        created_at=datetime.now(UTC),
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return provider


@pytest.mark.asyncio
async def test_jit_provision_new_user(db: AsyncSession):
    from sso_service import jit_provision_user

    provider = await _create_provider(db)
    user, created = await jit_provision_user(
        db, provider, external_id="ext-1", email="new@test.com", name="New"
    )
    assert created is True
    assert user.email == "new@test.com"
    assert user.role == Role.user


@pytest.mark.asyncio
async def test_jit_provision_existing_external_identity(db: AsyncSession):
    from sso_service import jit_provision_user

    provider = await _create_provider(db)

    # First login
    user1, created1 = await jit_provision_user(
        db, provider, external_id="ext-2", email="repeat@test.com", name="Repeat"
    )
    assert created1 is True

    # Second login — same external_id
    user2, created2 = await jit_provision_user(
        db, provider, external_id="ext-2", email="repeat@test.com", name="Repeat"
    )
    assert created2 is False
    assert user1.id == user2.id


@pytest.mark.asyncio
async def test_jit_provision_links_existing_email(db: AsyncSession):

    from sso_service import jit_provision_user

    # Create a user manually (e.g., registered via local auth)
    existing = User(
        email="existing@test.com",
        name="Existing",
        password_hash="hashed",
        role=Role.user,
    )
    db.add(existing)
    await db.commit()
    await db.refresh(existing)

    provider = await _create_provider(db)

    # SSO login with same email — should link, not create
    user, created = await jit_provision_user(
        db, provider, external_id="ext-3", email="existing@test.com", name="Existing"
    )
    assert created is False
    assert user.id == existing.id

    # Verify external identity was created
    result = await db.execute(
        select(ExternalIdentity).where(ExternalIdentity.user_id == existing.id)
    )
    assert result.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_apply_claim_mappings_exact_match(db: AsyncSession):

    from models import ClaimRoleMapping
    from sso_service import apply_claim_mappings

    provider = await _create_provider(db)

    # Get the reader system role
    result = await db.execute(
        select(DbRole).where(DbRole.name == "reader", DbRole.is_system.is_(True))
    )
    reader_role = result.scalar_one()

    # Create claim mapping
    mapping = ClaimRoleMapping(
        provider_id=provider.id,
        claim_key="department",
        claim_value_pattern="sales",
        role_id=reader_role.id,
    )
    db.add(mapping)
    await db.commit()

    # Create user
    user = User(email="claims@test.com", name="Claims", password_hash="x", role=Role.user)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    roles = await apply_claim_mappings(db, provider, user, {"department": "sales"})
    assert "reader" in roles

    # Verify UserRole created
    result = await db.execute(select(UserRole).where(UserRole.user_id == user.id))
    assert result.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_apply_claim_mappings_regex(db: AsyncSession):
    from models import ClaimRoleMapping
    from sso_service import apply_claim_mappings

    provider = await _create_provider(db)

    result = await db.execute(
        select(DbRole).where(DbRole.name == "user", DbRole.is_system.is_(True))
    )
    user_role = result.scalar_one()

    mapping = ClaimRoleMapping(
        provider_id=provider.id,
        claim_key="groups",
        claim_value_pattern="eng.*",
        role_id=user_role.id,
        is_regex=True,
    )
    db.add(mapping)
    await db.commit()

    user = User(email="regex@test.com", name="Regex", password_hash="x", role=Role.pending)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    roles = await apply_claim_mappings(db, provider, user, {"groups": ["engineering"]})
    assert "user" in roles


@pytest.mark.asyncio
async def test_apply_claim_mappings_no_match(db: AsyncSession):
    from sso_service import apply_claim_mappings

    provider = await _create_provider(db)
    user = User(email="nomatch@test.com", name="NoMatch", password_hash="x", role=Role.user)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    roles = await apply_claim_mappings(db, provider, user, {"other_key": "value"})
    assert roles == []


@pytest.mark.asyncio
async def test_issue_sso_tokens(db: AsyncSession):
    from sso_service import issue_sso_tokens

    user = User(email="tokens@test.com", name="Tokens", password_hash="x", role=Role.user)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    access, refresh = await issue_sso_tokens(db, user)
    assert len(access) > 0
    assert len(refresh) > 0
