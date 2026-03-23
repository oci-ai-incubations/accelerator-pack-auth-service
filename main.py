from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import (
    create_token,
    get_current_user,
    hash_password,
    require_admin,
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
    RegisterRequest,
    TokenResponse,
    UpdateUserRequest,
    UserResponse,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="aRBi Auth Service", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────


@app.get("/auth/health")
async def health():
    return {"status": "healthy", "service": "auth"}


# ── Registration & Login ──────────────────────────


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    # First user becomes admin automatically
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

    token = create_token(user)
    return TokenResponse(access_token=token, user=UserResponse.model_validate(user))


@app.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    token = create_token(user)
    return TokenResponse(access_token=token, user=UserResponse.model_validate(user))


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
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if req.role is not None:
        user.role = req.role
    if req.is_active is not None:
        user.is_active = req.is_active
    if req.name is not None:
        user.name = req.name

    await db.commit()
    await db.refresh(user)
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
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # Check user exists
    user_result = await db.execute(select(User).where(User.id == req.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Upsert: delete existing then insert
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
    _admin: User = Depends(require_admin),
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
    # Admins see all collections — return empty list (frontend interprets as "all access")
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
