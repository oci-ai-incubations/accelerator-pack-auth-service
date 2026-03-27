from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

import scim_service
from auth import (
    blacklist_token,
    check_account_lockout,
    clear_failed_attempts,
    create_access_token,
    create_refresh_token_value,
    decode_token,
    enforce_session_limit,
    get_current_user,
    hash_password,
    log_audit,
    record_failed_login,
    require_admin,
    require_permission,
    revoke_user_tokens,
    store_refresh_token,
    validate_refresh_token,
    verify_password,
)
from config import settings
from database import get_db, init_db
from models import (
    ClaimRoleMapping,
    CollectionPermission,
    DbRole,
    IdentityProvider,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from schemas import (
    ClaimMappingCreate,
    ClaimMappingResponse,
    CollectionPermissionRequest,
    CollectionPermissionResponse,
    LoginRequest,
    MyCollectionAccess,
    PermissionCheck,
    PermissionCheckResult,
    PermissionResponse,
    ProviderCreate,
    ProviderResponse,
    ProviderUpdate,
    RefreshRequest,
    RegisterRequest,
    RevokeRequest,
    RoleCreate,
    RolePermissionUpdate,
    RoleResponse,
    RoleUpdate,
    TokenResponse,
    UpdateUserRequest,
    UserResponse,
    UserRoleAssign,
    UserRoleResponse,
)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    # Seed system roles and permissions
    from database import async_session
    from permission_service import seed_roles_and_permissions

    async with async_session() as db:
        await seed_roles_and_permissions(db)
    yield


app = FastAPI(title="aRBi Auth Service", version="2.0.0", lifespan=lifespan)
app.state.limiter = limiter

# CORS — configurable via AUTH_CORS_ORIGINS
origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _require_local_auth():
    if not settings.local_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local authentication is disabled. Use SSO.",
        )


def _build_token_response(access_token: str, refresh_token: str, user: User) -> TokenResponse:
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
    )


# ── Health ────────────────────────────────────────


@app.get("/auth/health")
async def health():
    return {"status": "healthy", "service": "auth", "version": "3.0.0"}


@app.get("/auth/alive")
async def alive():
    return {"status": "alive"}


# ── Registration & Login ──────────────────────────


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_register)
async def register(request: Request, req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    _require_local_auth()
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user_count = await db.scalar(select(func.count()).select_from(User))
    role = Role.admin if user_count == 0 and settings.auto_admin_first_user else Role.pending

    user = User(
        email=req.email,
        name=req.name,
        password_hash=hash_password(req.password),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await enforce_session_limit(db, user.id)
    access_token = create_access_token(user)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)

    return _build_token_response(access_token, refresh_value, user)


@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit(settings.rate_limit_login)
async def login(request: Request, req: LoginRequest, db: AsyncSession = Depends(get_db)):
    _require_local_auth()
    await check_account_lockout(db, req.email)

    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(req.password, user.password_hash):
        ip = request.client.host if request.client else None
        await record_failed_login(db, req.email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    await clear_failed_attempts(db, req.email)
    await enforce_session_limit(db, user.id)

    access_token = create_access_token(user)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)

    return _build_token_response(access_token, refresh_value, user)


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    stored = await validate_refresh_token(db, req.refresh_token)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    # Revoke the used refresh token (rotation)
    stored.revoked = True
    await db.commit()

    # Load user
    result = await db.execute(select(User).where(User.id == stored.user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive"
        )

    # Issue new token pair
    new_access = create_access_token(user)
    new_refresh = create_refresh_token_value()
    await store_refresh_token(db, user.id, new_refresh)

    return _build_token_response(new_access, new_refresh, user)


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Blacklist the current access token
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    if token:
        payload = decode_token(token)
        jti = payload.get("jti")
        if jti:
            exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
            await blacklist_token(db, jti, exp)
    # Revoke all refresh tokens
    await revoke_user_tokens(db, user.id)


@app.post("/auth/token/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    req: RevokeRequest,
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    payload = decode_token(req.token)
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has no JTI")
    exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
    await blacklist_token(db, jti, exp)


# ── Current User ──────────────────────────────────


@app.get("/auth/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    return UserResponse.model_validate(user)


# ── User Management (admin only) ─────────────────


@app.get("/auth/users", response_model=list[UserResponse])
async def list_users(_admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@app.patch("/auth/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    req: UpdateUserRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    changes = []
    if req.role is not None:
        changes.append(f"role: {user.role} -> {req.role}")
        user.role = req.role
    if req.is_active is not None:
        changes.append(f"active: {user.is_active} -> {req.is_active}")
        user.is_active = req.is_active
    if req.name is not None:
        user.name = req.name

    await db.commit()
    await db.refresh(user)

    if changes:
        await log_audit(db, admin.id, "update_user", f"user={user_id} {', '.join(changes)}")

    return UserResponse.model_validate(user)


# ── Collection Permissions (admin only) ───────────


@app.post(
    "/auth/collections/{collection_id}/permissions",
    response_model=CollectionPermissionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def assign_collection_permission(
    collection_id: str,
    req: CollectionPermissionRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(select(User).where(User.id == req.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    await db.execute(
        delete(CollectionPermission).where(
            CollectionPermission.user_id == req.user_id,
            CollectionPermission.collection_id == collection_id,
        )
    )

    perm = CollectionPermission(
        user_id=req.user_id,
        collection_id=collection_id,
        permission_level=req.permission_level,
    )
    db.add(perm)
    await db.commit()
    await db.refresh(perm)

    await log_audit(
        db,
        admin.id,
        "assign_permission",
        f"user={req.user_id} collection={collection_id} level={req.permission_level}",
    )

    return CollectionPermissionResponse(
        id=perm.id,
        user_id=perm.user_id,
        collection_id=perm.collection_id,
        permission_level=perm.permission_level,
        user_email=user.email,
    )


@app.delete(
    "/auth/collections/{collection_id}/permissions/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_collection_permission(
    collection_id: str,
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        delete(CollectionPermission).where(
            CollectionPermission.user_id == user_id,
            CollectionPermission.collection_id == collection_id,
        )
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    await db.commit()
    await log_audit(db, admin.id, "revoke_permission", f"user={user_id} collection={collection_id}")


@app.get(
    "/auth/collections/{collection_id}/permissions",
    response_model=list[CollectionPermissionResponse],
)
async def list_collection_permissions(
    collection_id: str,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CollectionPermission, User.email)
        .join(User, CollectionPermission.user_id == User.id)
        .where(CollectionPermission.collection_id == collection_id)
    )
    return [
        CollectionPermissionResponse(
            id=perm.id,
            user_id=perm.user_id,
            collection_id=perm.collection_id,
            permission_level=perm.permission_level,
            user_email=email,
        )
        for perm, email in result.all()
    ]


@app.get("/auth/collections/my-access", response_model=list[MyCollectionAccess])
async def get_my_collection_access(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if user.role == Role.admin:
        return []

    result = await db.execute(
        select(CollectionPermission).where(CollectionPermission.user_id == user.id)
    )
    return [
        MyCollectionAccess(
            collection_id=p.collection_id,
            permission_level=p.permission_level,
        )
        for p in result.scalars().all()
    ]


# ── Roles (Phase 2, admin only) ───────────────────


async def _build_role_response(db: AsyncSession, role: DbRole) -> RoleResponse:
    result = await db.execute(
        select(Permission.codename)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role.id)
    )
    perms = [row[0] for row in result.all()]
    return RoleResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        is_default=role.is_default,
        tenant_id=role.tenant_id,
        permissions=perms,
        created_at=role.created_at,
    )


@app.get("/auth/roles", response_model=list[RoleResponse])
async def list_roles(
    _user: User = Depends(require_permission("roles:list")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DbRole).order_by(DbRole.name))
    roles = result.scalars().all()
    return [await _build_role_response(db, r) for r in roles]


@app.post("/auth/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    req: RoleCreate,
    admin: User = Depends(require_permission("roles:create")),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(
        select(DbRole).where(DbRole.name == req.name, DbRole.tenant_id == req.tenant_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role name already exists")

    role = DbRole(
        name=req.name,
        description=req.description,
        tenant_id=req.tenant_id,
        created_at=datetime.now(UTC),
    )
    db.add(role)
    await db.commit()
    await db.refresh(role)
    await log_audit(db, admin.id, "create_role", f"role={role.name}")
    return await _build_role_response(db, role)


@app.get("/auth/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: int,
    _user: User = Depends(require_permission("roles:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DbRole).where(DbRole.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return await _build_role_response(db, role)


@app.patch("/auth/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: int,
    req: RoleUpdate,
    admin: User = Depends(require_permission("roles:update")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DbRole).where(DbRole.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify system roles"
        )

    if req.name is not None:
        role.name = req.name
    if req.description is not None:
        role.description = req.description
    if req.is_default is not None:
        role.is_default = req.is_default

    await db.commit()
    await db.refresh(role)
    await log_audit(db, admin.id, "update_role", f"role={role_id}")
    return await _build_role_response(db, role)


@app.delete("/auth/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: int,
    admin: User = Depends(require_permission("roles:delete")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DbRole).where(DbRole.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete system roles"
        )
    await db.delete(role)
    await db.commit()
    await log_audit(db, admin.id, "delete_role", f"role={role.name}")


@app.put("/auth/roles/{role_id}/permissions", response_model=RoleResponse)
async def set_role_permissions(
    role_id: int,
    req: RolePermissionUpdate,
    admin: User = Depends(require_permission("roles:update")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DbRole).where(DbRole.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify system role permissions"
        )

    # Clear existing and set new
    await db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    for codename in req.permission_codenames:
        perm_result = await db.execute(select(Permission).where(Permission.codename == codename))
        perm = perm_result.scalar_one_or_none()
        if perm:
            db.add(RolePermission(role_id=role_id, permission_id=perm.id))
    await db.commit()
    await log_audit(db, admin.id, "set_role_permissions", f"role={role_id}")
    return await _build_role_response(db, role)


# ── Permissions (Phase 2) ────────────────────────


@app.get("/auth/permissions", response_model=list[PermissionResponse])
async def list_permissions(
    _user: User = Depends(require_permission("permissions:list")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Permission).order_by(Permission.codename))
    return [PermissionResponse.model_validate(p) for p in result.scalars().all()]


@app.post("/auth/permissions/check", response_model=PermissionCheckResult)
async def check_user_permission(
    req: PermissionCheck,
    _admin: User = Depends(require_permission("permissions:check")),
    db: AsyncSession = Depends(get_db),
):
    from permission_service import check_permission

    user_result = await db.execute(select(User).where(User.id == req.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    allowed = await check_permission(db, user, req.permission, req.resource_type, req.resource_id)
    return PermissionCheckResult(allowed=allowed, permission=req.permission, user_id=req.user_id)


# ── User Role Assignments (Phase 2) ──────────────


@app.get("/auth/users/{user_id}/roles", response_model=list[UserRoleResponse])
async def list_user_roles(
    user_id: int,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserRole, DbRole.name)
        .join(DbRole, UserRole.role_id == DbRole.id)
        .where(UserRole.user_id == user_id)
    )
    return [
        UserRoleResponse(
            id=ur.id,
            user_id=ur.user_id,
            role_id=ur.role_id,
            role_name=name,
            tenant_id=ur.tenant_id,
            scope_type=ur.scope_type,
            scope_id=ur.scope_id,
            created_at=ur.created_at,
        )
        for ur, name in result.all()
    ]


@app.post(
    "/auth/users/{user_id}/roles",
    response_model=UserRoleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def assign_user_role(
    user_id: int,
    req: UserRoleAssign,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # Verify user exists
    user_result = await db.execute(select(User).where(User.id == user_id))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Verify role exists
    role_result = await db.execute(select(DbRole).where(DbRole.id == req.role_id))
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    assignment = UserRole(
        user_id=user_id,
        role_id=req.role_id,
        tenant_id=req.tenant_id,
        scope_type=req.scope_type,
        scope_id=req.scope_id,
        granted_by=admin.id,
        created_at=datetime.now(UTC),
    )
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    await log_audit(db, admin.id, "assign_role", f"user={user_id} role={role.name}")

    return UserRoleResponse(
        id=assignment.id,
        user_id=assignment.user_id,
        role_id=assignment.role_id,
        role_name=role.name,
        tenant_id=assignment.tenant_id,
        scope_type=assignment.scope_type,
        scope_id=assignment.scope_id,
        created_at=assignment.created_at,
    )


@app.delete("/auth/users/{user_id}/roles/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user_role(
    user_id: int,
    assignment_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserRole).where(UserRole.id == assignment_id, UserRole.user_id == user_id)
    )
    assignment = result.scalar_one_or_none()
    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found"
        )
    await db.delete(assignment)
    await db.commit()
    await log_audit(db, admin.id, "remove_role", f"user={user_id} assignment={assignment_id}")


# ── Identity Providers (Phase 3) ──────────────────


@app.get("/auth/providers", response_model=list[ProviderResponse])
async def list_providers(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(IdentityProvider).order_by(IdentityProvider.priority.desc()))
    return [ProviderResponse.model_validate(p) for p in result.scalars().all()]


@app.post("/auth/providers", response_model=ProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(
    req: ProviderCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(IdentityProvider).where(IdentityProvider.slug == req.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already exists")

    provider = IdentityProvider(
        type=req.type,
        name=req.name,
        slug=req.slug,
        config=req.config,
        tenant_id=req.tenant_id,
        is_active=req.is_active,
        priority=req.priority,
        created_at=datetime.now(UTC),
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    await log_audit(db, admin.id, "create_provider", f"provider={provider.slug}")
    return ProviderResponse.model_validate(provider)


@app.get("/auth/providers/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: int,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(IdentityProvider).where(IdentityProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    return ProviderResponse.model_validate(provider)


@app.patch("/auth/providers/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: int,
    req: ProviderUpdate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(IdentityProvider).where(IdentityProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    if req.name is not None:
        provider.name = req.name
    if req.config is not None:
        provider.config = req.config
    if req.is_active is not None:
        provider.is_active = req.is_active
    if req.priority is not None:
        provider.priority = req.priority

    await db.commit()
    await db.refresh(provider)
    await log_audit(db, admin.id, "update_provider", f"provider={provider_id}")
    return ProviderResponse.model_validate(provider)


@app.delete("/auth/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(IdentityProvider).where(IdentityProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    await db.delete(provider)
    await db.commit()
    await log_audit(db, admin.id, "delete_provider", f"provider={provider.slug}")


# ── Claim Mappings (Phase 3) ─────────────────────


@app.get("/auth/providers/{provider_id}/mappings", response_model=list[ClaimMappingResponse])
async def list_claim_mappings(
    provider_id: int,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ClaimRoleMapping)
        .where(ClaimRoleMapping.provider_id == provider_id)
        .order_by(ClaimRoleMapping.priority.desc())
    )
    return [ClaimMappingResponse.model_validate(m) for m in result.scalars().all()]


@app.post(
    "/auth/providers/{provider_id}/mappings",
    response_model=ClaimMappingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_claim_mapping(
    provider_id: int,
    req: ClaimMappingCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # Verify provider exists
    prov_result = await db.execute(
        select(IdentityProvider).where(IdentityProvider.id == provider_id)
    )
    if not prov_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    # Verify role exists
    role_result = await db.execute(select(DbRole).where(DbRole.id == req.role_id))
    if not role_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    mapping = ClaimRoleMapping(
        provider_id=provider_id,
        claim_key=req.claim_key,
        claim_value_pattern=req.claim_value_pattern,
        role_id=req.role_id,
        priority=req.priority,
        is_regex=req.is_regex,
    )
    db.add(mapping)
    await db.commit()
    await db.refresh(mapping)
    await log_audit(db, admin.id, "create_claim_mapping", f"provider={provider_id}")
    return ClaimMappingResponse.model_validate(mapping)


@app.delete(
    "/auth/providers/{provider_id}/mappings/{mapping_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_claim_mapping(
    provider_id: int,
    mapping_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ClaimRoleMapping).where(
            ClaimRoleMapping.id == mapping_id,
            ClaimRoleMapping.provider_id == provider_id,
        )
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mapping not found")
    await db.delete(mapping)
    await db.commit()
    await log_audit(db, admin.id, "delete_claim_mapping", f"mapping={mapping_id}")


# ── SSO Callback (Phase 3) ───────────────────────


@app.post("/auth/sso/callback", response_model=TokenResponse)
async def sso_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Generic SSO callback — called by OIDC/SAML handlers after external auth.

    Expects JSON body with: provider_slug, external_id, email, name, claims.
    In production, the OIDC callback and SAML ACS endpoints validate the
    external token/assertion and then call this internally.
    """
    body = await request.json()
    slug = body.get("provider_slug")
    if not slug:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="provider_slug required"
        )

    result = await db.execute(
        select(IdentityProvider).where(
            IdentityProvider.slug == slug, IdentityProvider.is_active.is_(True)
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    from sso_service import apply_claim_mappings, issue_sso_tokens, jit_provision_user

    user, _created = await jit_provision_user(
        db,
        provider,
        external_id=body.get("external_id", ""),
        email=body.get("email", ""),
        name=body.get("name", "SSO User"),
        raw_claims=body.get("claims"),
    )

    claims = body.get("claims", {})
    await apply_claim_mappings(db, provider, user, claims)

    access_token, refresh_value = await issue_sso_tokens(db, user)
    return _build_token_response(access_token, refresh_value, user)


# ── Groups (Phase 4, admin) ───────────────────────


@app.get("/auth/groups")
async def list_groups(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from models import Group

    result = await db.execute(select(Group).order_by(Group.name))
    groups = result.scalars().all()
    return [
        {
            "id": g.id,
            "name": g.name,
            "display_name": g.display_name,
            "source": g.source.value if g.source else "local",
            "external_id": g.external_id,
        }
        for g in groups
    ]


@app.post("/auth/groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from models import Group

    body = await request.json()
    group = Group(
        name=body["name"],
        display_name=body.get("display_name", body["name"]),
        description=body.get("description"),
        created_at=datetime.now(UTC),
    )
    db.add(group)
    await db.commit()
    await db.refresh(group)
    await log_audit(db, admin.id, "create_group", f"group={group.name}")
    return {"id": group.id, "name": group.name, "display_name": group.display_name}


@app.get("/auth/groups/{group_id}/members")
async def list_group_members(
    group_id: int,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from models import GroupMembership

    result = await db.execute(
        select(User)
        .join(GroupMembership, GroupMembership.user_id == User.id)
        .where(GroupMembership.group_id == group_id)
    )
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@app.post("/auth/groups/{group_id}/members", status_code=status.HTTP_201_CREATED)
async def add_group_member(
    group_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from models import GroupMembership

    body = await request.json()
    user_id = body["user_id"]
    db.add(GroupMembership(group_id=group_id, user_id=user_id))
    await db.commit()
    await log_audit(db, admin.id, "add_group_member", f"group={group_id} user={user_id}")
    return {"group_id": group_id, "user_id": user_id}


@app.delete(
    "/auth/groups/{group_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_group_member(
    group_id: int,
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from models import GroupMembership

    result = await db.execute(
        select(GroupMembership).where(
            GroupMembership.group_id == group_id,
            GroupMembership.user_id == user_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membership not found")
    await db.delete(membership)
    await db.commit()


@app.put("/auth/groups/{group_id}/roles")
async def set_group_roles(
    group_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from models import GroupRole

    body = await request.json()
    role_ids = body.get("role_ids", [])

    # Clear existing
    await db.execute(delete(GroupRole).where(GroupRole.group_id == group_id))

    for rid in role_ids:
        db.add(GroupRole(group_id=group_id, role_id=rid))
    await db.commit()
    await log_audit(db, admin.id, "set_group_roles", f"group={group_id}")
    return {"group_id": group_id, "role_ids": role_ids}


# ── SCIM 2.0 (Phase 4) ──────────────────────────


@app.get("/scim/v2/ServiceProviderConfig")
async def scim_service_provider_config(
    _token: str = Depends(scim_service.require_scim_auth),
):
    return scim_service.SCIM_SERVICE_PROVIDER_CONFIG


@app.get("/scim/v2/Schemas")
async def scim_schemas(_token: str = Depends(scim_service.require_scim_auth)):
    return scim_service.SCIM_SCHEMAS


@app.get("/scim/v2/ResourceTypes")
async def scim_resource_types(_token: str = Depends(scim_service.require_scim_auth)):
    return scim_service.SCIM_RESOURCE_TYPES


@app.get("/scim/v2/Users")
async def scim_list_users(
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).order_by(User.id))
    users = result.scalars().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(users),
        "Resources": [scim_service.user_to_scim(u) for u in users],
    }


@app.post("/scim/v2/Users", status_code=status.HTTP_201_CREATED)
async def scim_create_user_endpoint(
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    data = await request.json()
    user = await scim_service.scim_create_user(db, data)
    return scim_service.user_to_scim(user)


@app.get("/scim/v2/Users/{user_id}")
async def scim_get_user(
    user_id: int,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return scim_service.user_to_scim(user)


@app.put("/scim/v2/Users/{user_id}")
async def scim_replace_user(
    user_id: int,
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    data = await request.json()
    user = await scim_service.scim_update_user(db, user, data)
    return scim_service.user_to_scim(user)


@app.delete("/scim/v2/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def scim_delete_user(
    user_id: int,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.is_active = False
    await db.commit()
    await revoke_user_tokens(db, user.id)


@app.get("/scim/v2/Groups")
async def scim_list_groups(
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from models import Group

    result = await db.execute(select(Group).order_by(Group.id))
    groups = result.scalars().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(groups),
        "Resources": [scim_service.group_to_scim(g) for g in groups],
    }


@app.post("/scim/v2/Groups", status_code=status.HTTP_201_CREATED)
async def scim_create_group_endpoint(
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    data = await request.json()
    group = await scim_service.scim_create_group(db, data)
    return scim_service.group_to_scim(group)


@app.get("/scim/v2/Groups/{group_id}")
async def scim_get_group(
    group_id: int,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from models import Group

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return scim_service.group_to_scim(group)


@app.put("/scim/v2/Groups/{group_id}")
async def scim_replace_group(
    group_id: int,
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from models import Group

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    data = await request.json()
    group = await scim_service.scim_update_group(db, group, data)
    return scim_service.group_to_scim(group)


@app.delete("/scim/v2/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def scim_delete_group(
    group_id: int,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from models import Group

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await db.delete(group)
    await db.commit()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)  # noqa: S104
