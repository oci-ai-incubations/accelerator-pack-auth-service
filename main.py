from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import (
    create_access_token,
    create_refresh_token_value,
    get_current_user,
    hash_password,
    log_audit,
    require_admin,
    revoke_user_tokens,
    store_refresh_token,
    validate_refresh_token,
    verify_password,
)
from config import settings
from database import get_db, init_db
from models import CollectionPermission, Role, User
from schemas import (
    CollectionPermissionRequest,
    CollectionPermissionResponse,
    LoginRequest,
    MyCollectionAccess,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UpdateUserRequest,
    UserResponse,
)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
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
    return {"status": "healthy", "service": "auth", "version": "2.0.0"}


# ── Registration & Login ──────────────────────────


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_register)
async def register(request: Request, req: RegisterRequest, db: AsyncSession = Depends(get_db)):
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

    access_token = create_access_token(user)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)

    return _build_token_response(access_token, refresh_value, user)


@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit(settings.rate_limit_login)
async def login(request: Request, req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

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
async def logout(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await revoke_user_tokens(db, user.id)


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)  # noqa: S104
