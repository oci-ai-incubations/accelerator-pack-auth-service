"""Seeding from a pack model is idempotent and produces the model's roles + perms."""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from accelerator_pack_auth_service.models import Base, DbRole, Permission
from accelerator_pack_auth_service.pack_models import BASE_MODEL, CUOPT_MODEL, PAAS_RAG_MODEL
from accelerator_pack_auth_service.permission_service import seed_roles_and_permissions


@pytest.mark.asyncio
async def test_seed_cuopt_produces_cuopt_perms():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as db:
            await seed_roles_and_permissions(db, model=CUOPT_MODEL)
            perms = (await db.execute(select(Permission.codename))).scalars().all()
            roles = (await db.execute(select(DbRole.name))).scalars().all()
        assert "cuopt.solve" in perms
        assert "cuopt.view" in perms
        assert "collections:read" not in perms  # paas_rag-only
        assert set(roles) == {"admin", "user", "reader"}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_seed_paas_rag_produces_collection_perms():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as db:
            await seed_roles_and_permissions(db, model=PAAS_RAG_MODEL)
            perms = (await db.execute(select(Permission.codename))).scalars().all()
            roles = (await db.execute(select(DbRole.name))).scalars().all()
        assert "collections:read" in perms
        assert "collections:write" in perms
        assert "cuopt.solve" not in perms
        assert set(roles) == {"admin", "user", "reader", "pending"}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_seed_is_idempotent():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as db:
            await seed_roles_and_permissions(db, model=BASE_MODEL)
            await seed_roles_and_permissions(db, model=BASE_MODEL)
            perm_count = len((await db.execute(select(Permission))).scalars().all())
            role_count = len((await db.execute(select(DbRole))).scalars().all())
        assert perm_count == len(BASE_MODEL.permissions)
        assert role_count == len(BASE_MODEL.roles)
    finally:
        await engine.dispose()
