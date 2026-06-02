import base64
import binascii
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import __version__, clients, scim_service
from .auth import (
    blacklist_token,
    check_account_lockout,
    clear_failed_attempts,
    create_access_token,
    create_client_access_token,
    create_refresh_token_value,
    decode_token,
    enforce_session_limit,
    get_current_user,
    hash_password,
    is_token_blacklisted,
    log_audit,
    record_failed_login,
    require_admin,
    require_pack_permission,
    require_permission,
    revoke_user_tokens,
    store_refresh_token,
    validate_refresh_token,
    verify_password,
)
from .config import settings
from .crypto import (
    jwks_entry_for_key,
    list_keys_for_jwks,
    revoke_key,
    rotate_active_key,
)
from .database import get_db, init_db
from .models import (
    AuditResult,
    ClaimRoleMapping,
    CollectionPermission,
    DbRole,
    IdentityProvider,
    Permission,
    PrincipalType,
    Role,
    RolePermission,
    ServiceAccount,
    SigningKey,
    User,
    UserRole,
)
from .pack_models import load_active_model
from .schemas import (
    ClaimMappingCreate,
    ClaimMappingResponse,
    CollectionPermissionRequest,
    CollectionPermissionResponse,
    LoginRequest,
    MyCollectionAccess,
    PackScopesResponse,
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
    ScopeDescription,
    ServiceAccountCreate,
    ServiceAccountResponse,
    ServiceAccountUpdate,
    ServiceAccountWithSecret,
    TokenResponse,
    UpdateUserRequest,
    UserResponse,
    UserRoleAssign,
    UserRoleResponse,
)
from .scopes import (
    InvalidScopeError,
    grant_scopes,
    parse_scope_string,
    resolve_effective_user_scopes,
)

# RFC 6749 §5.2 error codes for the OAuth2 token endpoint. Named here as a
# constant so route handlers never construct error bodies inline (drift risk
# on per-error error_description strings is the silent-correctness hazard the
# RFC was built to prevent).
OAUTH2_ERROR_INVALID_CLIENT = "invalid_client"
OAUTH2_ERROR_INVALID_REQUEST = "invalid_request"
OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
OAUTH2_ERROR_INVALID_SCOPE = "invalid_scope"

# RFC 6749 §5.1 mandates ``Cache-Control: no-store`` (and SHOULD ``Pragma: no-cache``)
# on every response that could carry tokens — success AND error variants. Named
# here so every token-bearing endpoint applies the same shape via
# ``_apply_no_store(response)`` / by returning ``_oauth2_error(..., no_store=True)``.
_NO_STORE_CACHE = "no-store"
_NO_CACHE_PRAGMA = "no-cache"


def _apply_no_store(response: Response) -> None:
    """Stamp RFC 6749 §5.1 anti-caching headers on a token-bearing response."""
    response.headers["Cache-Control"] = _NO_STORE_CACHE
    response.headers["Pragma"] = _NO_CACHE_PRAGMA


limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    # Seed system roles and permissions, and ensure an active signing key
    # exists so the JWKS endpoint is non-empty before the first registration.
    from .crypto import get_active_signing_key
    from .database import async_session
    from .permission_service import seed_roles_and_permissions

    async with async_session() as session:
        await seed_roles_and_permissions(session)
        await get_active_signing_key(session)
    yield


OPENAPI_TAGS = [
    {"name": "Health", "description": "Liveness, readiness, and pack-model discovery."},
    {
        "name": "Authentication",
        "description": "Login, registration, refresh, logout, and token revocation.",
    },
    {"name": "Current User", "description": "Profile of the authenticated user."},
    {"name": "Users", "description": "User management (admin only)."},
    {
        "name": "Collections",
        "description": "Per-collection permission grants (legacy paas_rag model).",
    },
    {"name": "Roles", "description": "RBAC role CRUD and permission assignments (admin)."},
    {"name": "Permissions", "description": "Permission catalog and per-user checks (admin)."},
    {"name": "User Roles", "description": "Assign or revoke roles on a user (admin)."},
    {
        "name": "Identity Providers",
        "description": "OIDC/SAML provider configuration (admin).",
    },
    {"name": "Claim Mappings", "description": "Map IdP claims to internal roles (admin)."},
    {
        "name": "SSO",
        "description": "Public discovery, IdP authorize URL build, and code/token exchange.",
    },
    {"name": "Groups", "description": "Group CRUD, membership, and group→role binding (admin)."},
    {"name": "SCIM", "description": "SCIM 2.0 user/group provisioning (bearer-token gated)."},
    {"name": "Audit", "description": "Audit log query, export, and retention purge."},
    {"name": "Admin", "description": "Admin dashboard status + feature flags."},
    {
        "name": "Discovery",
        "description": "Public OIDC discovery + JWKS endpoints for token verifiers.",
    },
    {
        "name": "Signing Keys",
        "description": "RS256 signing-key lifecycle: list, rotate, revoke (admin).",
    },
    {
        "name": "OAuth2",
        "description": "RFC 6749 token endpoints (client_credentials grant).",
    },
    {
        "name": "Service Accounts",
        "description": "Admin CRUD + secret rotation for OAuth2 client_credentials principals.",
    },
    {
        "name": "Scopes",
        "description": "Active pack's scope vocabulary for admin UI scope pickers.",
    },
]


app = FastAPI(
    title="OCI AI Accelerator Auth Service",
    version=__version__,
    description=(
        "Pluggable per-user JWT authentication, RBAC, OIDC/SAML SSO, SCIM 2.0 "
        "provisioning, and audit logging for OCI AI Accelerator packs. Customers "
        "integrate by fetching this OpenAPI document, generating a typed client, "
        "and calling `/auth/*` from their applications."
    ),
    # Unconditionally exposed (no DEBUG gate): auth-service has no ingress —
    # only the pack frontend's /auth/* prefix routes to it, and /docs etc. fall
    # outside that prefix, so the surface is cluster-internal. Pack BEs (cuopt,
    # vss, …) DO have ingress and MUST gate their docs by DEBUG=false.
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name": "OCI AI Accelerator Team",
        "url": "https://github.com/oci-ai-incubations/accelerator-pack-auth-service",
    },
    license_info={
        "name": "Universal Permissive License v1.0",
        "url": "https://oss.oracle.com/licenses/upl",
    },
    servers=[
        {"url": "http://localhost:8080", "description": "Local development"},
    ],
    openapi_tags=OPENAPI_TAGS,
    lifespan=lifespan,
)
app.state.limiter = limiter
# Wire the slowapi exception handler + middleware. Without these, raising
# RateLimitExceeded bubbles up as a generic 500 (we'd be back-off-blind),
# and routes lacking an explicit @limiter.limit decorator would have no
# per-IP cap at all. The handler emits a clean 429 with a Retry-After.
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


def custom_openapi() -> dict:
    """Return the OpenAPI schema with a bearerAuth security scheme applied globally.

    Public endpoints opt out per-route by passing
    ``openapi_extra={"security": []}`` in their decorator; everything else
    inherits the default Bearer requirement so the Swagger UI lock icon
    reflects reality.
    """
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=OPENAPI_TAGS,
        servers=app.servers,
        contact=app.contact,
        license_info=app.license_info,
    )
    schema.setdefault("components", {})["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "JWT access token from `POST /auth/login` or `POST /auth/sso/{slug}/token`."
            ),
        }
    }
    schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi

# CORS — configurable via AUTH_CORS_ORIGINS (comma-separated). Default is
# empty (no cross-origin requests permitted) — operators must explicitly
# allowlist the pack frontend's origin. If a wildcard "*" appears in the
# list we force allow_credentials=False per the CORS spec (Starlette would
# silently fail to echo Access-Control-Allow-Credentials in that case;
# being explicit makes the intent visible). Methods and headers are
# enumerated rather than wildcarded.
origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
_cors_has_wildcard = "*" in origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=not _cors_has_wildcard,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


# Security headers middleware. Permissions-Policy denies camera/mic/geolocation
# (auth-service doesn't need them). CSP for the JSON API surface: no scripts,
# no inline content, framing denied — the admin UI is on a separate origin
# (the pack frontend) so this host serves only API responses.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    # HSTS pins the host to HTTPS for max-age, with no user override path —
    # gate on production mode (AUTH_DEBUG=false). Demo clusters with
    # self-signed certs hit by HSTS-pinned browsers become unreachable
    # without clearing chrome://net-internals/#hsts state. Production
    # deployments with valid certs DO want HSTS; the gate is the standard.
    if not settings.debug:
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


@app.get(
    "/auth/health",
    summary="Readiness probe",
    description=(
        "Lightweight readiness check. Returns `{status, service, version}`. "
        "Public — no authentication required. Used by ingress and Kubernetes "
        "readinessProbe."
    ),
    tags=["Health"],
    responses={200: {"description": "Service is healthy"}},
    openapi_extra={"security": []},
)
async def health():
    return {"status": "healthy", "service": "auth"}


@app.get(
    "/auth/alive",
    summary="Liveness probe",
    description=(
        "Lightweight liveness check used by Kubernetes livenessProbe. Public — "
        "no authentication required. Returns `{status: alive}` whenever the "
        "process is up."
    ),
    tags=["Health"],
    responses={200: {"description": "Process is alive"}},
    openapi_extra={"security": []},
)
async def alive():
    return {"status": "alive"}


@app.get(
    "/auth/pack/model",
    summary="Get active pack auth model",
    description=(
        "Return the active `PackAuthModel` (pack_id, roles, permissions, "
        "role→permission map) selected by the `AUTH_PACK` env var. Public — "
        "frontends call this from the login page to discover which roles and "
        "admin tabs the deployment exposes so the UI renders only the relevant "
        "controls."
    ),
    tags=["Health"],
    responses={200: {"description": "Active pack model"}},
    openapi_extra={"security": []},
)
async def get_pack_model() -> dict:
    """Return the active pack auth model.

    Public — no auth required. Frontends call this to discover which roles +
    permissions the deployment supports so admin UIs can render only the
    relevant tabs.
    """
    return load_active_model(settings.pack).model_dump()


@app.get(
    "/auth/scopes",
    response_model=PackScopesResponse,
    summary="Get the active pack's scope vocabulary",
    description=(
        "Return every scope codename declared by the active pack model with "
        "its human-readable description. Drives the admin UI's scope picker "
        "(service-account creation, scoped user-token issuance). "
        "Authenticated — any logged-in principal can read; the contents "
        "aren't sensitive but anonymous discovery would let a scanner profile "
        "the deployment surface."
    ),
    tags=["Scopes"],
    responses={
        200: {"description": "Pack scope vocabulary"},
        401: {"description": "Token missing or invalid"},
    },
)
async def get_pack_scopes(_user: User = Depends(get_current_user)) -> PackScopesResponse:
    """Return the active pack model's scope codenames with descriptions.

    Sources the human-readable description from
    ``permission_service.PERMISSION_DESCRIPTIONS`` when available and falls
    back to ``Permission <codename>`` otherwise — the same convention as the
    seeding code so admin-UI labels match what's in the DB.
    """
    from .permission_service import _permission_meta

    pack_model = load_active_model(settings.pack)
    entries = [
        ScopeDescription(codename=codename, description=_permission_meta(codename)[0])
        for codename in pack_model.permissions
    ]
    return PackScopesResponse(pack_id=pack_model.pack_id, scopes=entries)


# ── OIDC Discovery & JWKS ────────────────────────


@app.get(
    "/auth/.well-known/jwks.json",
    summary="JSON Web Key Set",
    description=(
        "RFC 7517 JWKS document. Returns every signing key that is either "
        "active or within its 24h rotating_out grace window — revoked keys "
        "are excluded immediately. Pack backends fetch this URL, cache it "
        "for `AUTH_JWKS_CACHE_TTL`, and verify token signatures locally."
    ),
    tags=["Discovery"],
    responses={200: {"description": "JWKS document"}},
    openapi_extra={"security": []},
)
async def get_jwks(response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    keys = await list_keys_for_jwks(db)
    response.headers["Cache-Control"] = "public, max-age=3600"
    return {"keys": [jwks_entry_for_key(k) for k in keys]}


def _build_as_metadata() -> dict:
    """Return the RFC 8414 Authorization Server Metadata document.

    Auth-service is a token issuer, not a full OpenID Provider — we don't run
    an authorization_endpoint of our own (the password grant lives at
    ``/auth/login``, the client_credentials grant at ``/auth/oauth/token``).
    Strict OIDC Discovery 1.0 verifiers (``aud`` checkers backed by jwks_uri
    discovery, for example) accept this RFC 8414 shape; downstream callers
    that want a "real" OIDC discovery doc should point at the federated IdP's
    own ``.well-known/openid-configuration`` instead.

    ``response_types_supported`` is omitted because we don't run any
    authorization endpoint. ``grant_types_supported`` lists what we actually
    accept.
    """
    issuer = settings.issuer_url
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/me",
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "grant_types_supported": ["password", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
    }


@app.get(
    "/auth/.well-known/oauth-authorization-server",
    summary="OAuth 2.0 Authorization Server Metadata (RFC 8414)",
    description=(
        "RFC 8414 Authorization Server Metadata document. Auth-service is a "
        "token issuer rather than a full OpenID Provider — it has no "
        "authorization_endpoint of its own — so the AS-metadata shape is the "
        "honest description of the surface. Frontends and verifiers that "
        "need an OIDC Discovery 1.0 document can use the alias at "
        "`/auth/.well-known/openid-configuration`, which returns the same body."
    ),
    tags=["Discovery"],
    responses={
        200: {"description": "Authorization server metadata"},
        503: {"description": "Discovery not configured (AUTH_ISSUER_URL unset)"},
    },
    openapi_extra={"security": []},
)
async def get_as_metadata() -> dict:
    if not settings.issuer_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Discovery not configured",
        )
    return _build_as_metadata()


@app.get(
    "/auth/.well-known/openid-configuration",
    summary="OIDC discovery document (alias for RFC 8414 metadata)",
    description=(
        "OIDC Discovery 1.0-compatible alias for "
        "`/auth/.well-known/oauth-authorization-server`. Returns the same "
        "RFC 8414 Authorization Server Metadata body. We don't expose an "
        "authorization_endpoint because auth-service is a token issuer, not "
        "an authorization server in the auth-code sense — verifiers that "
        "need an authorization_endpoint should federate via an OIDC IdP."
    ),
    tags=["Discovery"],
    responses={
        200: {"description": "Discovery document"},
        503: {"description": "OIDC discovery not configured (AUTH_ISSUER_URL unset)"},
    },
    openapi_extra={"security": []},
)
async def get_oidc_discovery() -> dict:
    if not settings.issuer_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC discovery not configured",
        )
    return _build_as_metadata()


# ── Registration & Login ──────────────────────────


@app.post(
    "/auth/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new local user",
    description=(
        "Create a new local-auth user with email + password and return an "
        "access/refresh token pair. The first user registered on a fresh "
        "deployment is auto-elevated to `admin` when `AUTH_AUTO_ADMIN_FIRST_USER` "
        "is true (default); subsequent users are seeded with the `pending` role. "
        "Gated by `AUTH_LOCAL_AUTH_ENABLED` — returns 403 when only SSO is allowed."
    ),
    tags=["Authentication"],
    responses={
        201: {"description": "User created and token pair issued"},
        403: {"description": "Local authentication is disabled (SSO-only deployment)"},
        409: {"description": "Email already registered"},
        422: {"description": "Validation error on the request body"},
        429: {"description": "Registration rate limit exceeded"},
    },
    openapi_extra={"security": []},
)
@limiter.limit(settings.rate_limit_register)
async def register(
    request: Request,
    req: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    _require_local_auth()
    _apply_no_store(response)
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
    # No scope-request shape on register — defer to the user's full role
    # expansion so the freshly-minted token can do everything the role
    # allows. Issuers that want narrower default-scope tokens for new users
    # can pin via the per-user ``allowed_scopes`` override after creation.
    access_token = await create_access_token(db, user)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)

    return _build_token_response(access_token, refresh_value, user)


@app.post(
    "/auth/login",
    response_model=TokenResponse,
    summary="Log in with email + password",
    description=(
        "Authenticate a local user with email + password and return an "
        "access/refresh token pair. Failed attempts are recorded and trigger "
        "account lockout after `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` consecutive "
        "failures. Per-user concurrent sessions are capped at "
        "`AUTH_MAX_CONCURRENT_SESSIONS`."
    ),
    tags=["Authentication"],
    responses={
        200: {"description": "Token pair issued"},
        401: {"description": "Invalid credentials or account locked"},
        403: {"description": "Local authentication is disabled or account is deactivated"},
        422: {"description": "Validation error on the request body"},
        429: {"description": "Login rate limit exceeded"},
    },
    openapi_extra={"security": []},
)
@limiter.limit(settings.rate_limit_login)
async def login(
    request: Request,
    req: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    _require_local_auth()
    _apply_no_store(response)
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

    granted_scopes = await _grant_user_scopes(db, user, req.scope)
    access_token = await create_access_token(db, user, scopes=granted_scopes)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)

    return _build_token_response(access_token, refresh_value, user)


async def _grant_user_scopes(
    db: AsyncSession, user: User, requested_scope: str | None
) -> list[str]:
    """Resolve allowed-vs-requested scopes and raise OAuth2-shaped 400 on mismatch.

    Used by ``/auth/login``. Register and refresh always default-resolve via
    ``create_access_token`` and never narrow per-request — spec 003 doesn't
    define a scope parameter on those routes.

    A denial path writes an audit log with ``AuditResult.failure`` and the
    offending requested scope string so operators can spot integrators
    requesting scopes their role can't ever grant.
    """
    pack_model = load_active_model(settings.pack)
    # resolve_effective_user_scopes unions in UserRole-assigned permissions
    # so custom roles assigned via /auth/users/{id}/roles are honored at
    # login time, matching the runtime permission gate. Mirrors the same
    # helper used by create_access_token for register + refresh.
    allowed = await resolve_effective_user_scopes(db, user, pack_model)
    requested = parse_scope_string(requested_scope)
    try:
        return grant_scopes(allowed, requested, strict=settings.strict_scopes)
    except InvalidScopeError as exc:
        await log_audit(
            db,
            user.id,
            "login_invalid_scope",
            requested_scope or "",
            principal_type=PrincipalType.user,
            principal_id=str(user.id),
            result=AuditResult.failure,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": OAUTH2_ERROR_INVALID_SCOPE, "error_description": str(exc)},
        ) from exc


@app.post(
    "/auth/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description=(
        "Exchange a valid refresh token for a fresh access/refresh pair. The "
        "supplied refresh token is rotated out (marked revoked) and replaced "
        "with a new one, so each refresh token is single-use."
    ),
    tags=["Authentication"],
    responses={
        200: {"description": "New token pair issued"},
        401: {"description": "Refresh token invalid, expired, revoked, or user inactive"},
        422: {"description": "Validation error on the request body"},
    },
    openapi_extra={"security": []},
)
@limiter.limit(settings.rate_limit_refresh)
async def refresh_token(
    request: Request,
    req: RefreshRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    _apply_no_store(response)
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
    new_access = await create_access_token(db, user)
    new_refresh = create_refresh_token_value()
    await store_refresh_token(db, user.id, new_refresh)

    return _build_token_response(new_access, new_refresh, user)


@app.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out (revoke all sessions)",
    description=(
        "Blacklist the current access token (by its `jti` until natural "
        "expiry) and revoke every refresh token for the calling user — i.e. "
        "log out from all devices."
    ),
    tags=["Authentication"],
    responses={
        204: {"description": "Logged out; all sessions terminated"},
        401: {"description": "Access token missing or invalid"},
    },
)
@limiter.limit(settings.rate_limit_refresh)
async def logout(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Blacklist the current access token
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    if token:
        payload = await decode_token(db, token)
        jti = payload.get("jti")
        if jti:
            exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
            await blacklist_token(db, jti, exp)
    # Revoke all refresh tokens
    await revoke_user_tokens(db, user.id)


@app.post(
    "/auth/token/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a specific access token",
    description=(
        "Blacklist a specific access token by its `jti` claim until its "
        "natural expiry. Requires an authenticated caller — the calling token "
        "and the revoked token can be the same or different (admin revocation "
        "of another user's token is allowed)."
    ),
    tags=["Authentication"],
    responses={
        204: {"description": "Token revoked"},
        400: {"description": "Supplied token has no `jti` claim"},
        401: {"description": "Caller token missing or invalid"},
        422: {"description": "Validation error on the request body"},
    },
)
async def revoke_token(
    req: RevokeRequest,
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    payload = await decode_token(db, req.token)
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has no JTI")
    exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
    await blacklist_token(db, jti, exp)


# ── Current User ──────────────────────────────────


@app.get(
    "/auth/me",
    response_model=UserResponse,
    summary="Get the current user",
    description=(
        "Return the authenticated user's profile (id, email, name, role, "
        "active flag, timestamps). Used by pack frontends to populate the "
        "user menu and by pack backends as a cheap token-validation probe."
    ),
    tags=["Current User"],
    responses={
        200: {"description": "Authenticated user profile"},
        401: {"description": "Token missing, invalid, expired, or blacklisted"},
    },
)
async def get_me(user: User = Depends(get_current_user)):
    return UserResponse.model_validate(user)


# ── Token validation for downstream services (e.g. llama-stack CustomAuthProvider) ──
@app.post(
    "/auth/validate",
    summary="Validate a bearer token for a downstream service",
    tags=["Authentication"],
    responses={
        200: {"description": "Token is valid; returns principal, roles, and claims"},
        401: {"description": "Missing, expired, revoked, refresh-type, or otherwise invalid token"},
    },
)
async def validate_token_for_downstream(
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
    """Validate a bearer token on behalf of a downstream service.

    Services that delegate authentication to this service (e.g. llama-stack's
    CustomAuthProvider) POST ``{"api_key": "<jwt>"}`` and receive the principal
    and claims when the token is a valid, non-revoked access token.
    """
    token = payload.get("api_key", "")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    claims = await decode_token(db, token)
    if claims.get("type") == "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh tokens cannot authenticate"
        )

    jti = claims.get("jti")
    if jti and await is_token_blacklisted(db, jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    user_id = int(claims["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive"
        )

    return {
        "principal": str(user.id),
        "attributes": {
            "roles": [claims.get("role")] if claims.get("role") else [],
            "email": [user.email],
        },
    }


# ── User Management (admin only) ─────────────────


@app.get(
    "/auth/users",
    response_model=list[UserResponse],
    summary="List all users",
    description=(
        "Return every user in the deployment ordered by creation date (newest first). Admin only."
    ),
    tags=["Users"],
    responses={
        200: {"description": "List of users"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def list_users(_admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@app.patch(
    "/auth/users/{user_id}",
    response_model=UserResponse,
    summary="Update a user",
    description=(
        "Patch a user's role, active flag, or display name. Each change is "
        "written to the audit log with the admin's identity. Admin only."
    ),
    tags=["Users"],
    responses={
        200: {"description": "Updated user"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "User not found"},
        422: {"description": "Validation error on the request body"},
    },
)
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
    summary="Grant a user access to a collection",
    description=(
        "Assign a user a permission level on a specific collection. Replaces "
        "any existing grant for the (user, collection) pair. Legacy paas_rag "
        "model — prefer the role/permission CRUD endpoints for new packs. "
        "Admin only."
    ),
    tags=["Collections"],
    responses={
        201: {"description": "Permission granted"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "User not found"},
        422: {"description": "Validation error on the request body"},
    },
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
    summary="Revoke a user's access to a collection",
    description=("Remove a user's permission entry for a collection. Audit-logged. Admin only."),
    tags=["Collections"],
    responses={
        204: {"description": "Permission revoked"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Permission grant not found"},
    },
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
    summary="List a collection's permission grants",
    description=(
        "Return every user with explicit access to the collection, with "
        "their permission level and email. Admin only."
    ),
    tags=["Collections"],
    responses={
        200: {"description": "List of permission grants"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
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


@app.get(
    "/auth/collections/my-access",
    response_model=list[MyCollectionAccess],
    summary="List my collection access",
    description=(
        "Return the calling user's explicit per-collection permission grants. "
        "Returns an empty list for admin callers — admins have implicit "
        "access to every collection."
    ),
    tags=["Collections"],
    responses={
        200: {"description": "User's collection grants"},
        401: {"description": "Token missing or invalid"},
    },
)
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


@app.get(
    "/auth/roles",
    response_model=list[RoleResponse],
    summary="List roles",
    description=(
        "Return every role known to the deployment, with each role's bound "
        "permission codenames. Requires the `roles:list` permission."
    ),
    tags=["Roles"],
    responses={
        200: {"description": "List of roles"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `roles:list` permission"},
    },
)
async def list_roles(
    _user: User = Depends(require_permission("roles:list")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(DbRole).order_by(DbRole.name))
    roles = result.scalars().all()
    return [await _build_role_response(db, r) for r in roles]


@app.post(
    "/auth/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a role",
    description=(
        "Create a new tenant-scoped role. Role names must be unique within "
        "their tenant. Requires the `roles:create` permission."
    ),
    tags=["Roles"],
    responses={
        201: {"description": "Role created"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `roles:create` permission"},
        409: {"description": "Role name already exists in this tenant"},
        422: {"description": "Validation error on the request body"},
    },
)
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


@app.get(
    "/auth/roles/{role_id}",
    response_model=RoleResponse,
    summary="Get a role by id",
    description=(
        "Return a single role's definition and bound permissions. Requires "
        "the `roles:read` permission."
    ),
    tags=["Roles"],
    responses={
        200: {"description": "Role detail"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `roles:read` permission"},
        404: {"description": "Role not found"},
    },
)
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


@app.patch(
    "/auth/roles/{role_id}",
    response_model=RoleResponse,
    summary="Update a role",
    description=(
        "Patch a custom role's name, description, or default-assignment flag. "
        "System-seeded roles are immutable and return 403. Requires the "
        "`roles:update` permission."
    ),
    tags=["Roles"],
    responses={
        200: {"description": "Updated role"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "System role cannot be modified, or caller lacks `roles:update`"},
        404: {"description": "Role not found"},
        422: {"description": "Validation error on the request body"},
    },
)
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


@app.delete(
    "/auth/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a role",
    description=(
        "Delete a custom role. System-seeded roles cannot be deleted and "
        "return 403. Requires the `roles:delete` permission."
    ),
    tags=["Roles"],
    responses={
        204: {"description": "Role deleted"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "System role cannot be deleted, or caller lacks `roles:delete`"},
        404: {"description": "Role not found"},
    },
)
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


@app.put(
    "/auth/roles/{role_id}/permissions",
    response_model=RoleResponse,
    summary="Set a role's permissions",
    description=(
        "Replace the full permission set bound to a custom role. Unknown "
        "permission codenames in the payload are silently skipped. System "
        "roles return 403. Requires the `roles:update` permission."
    ),
    tags=["Roles"],
    responses={
        200: {"description": "Role permissions updated"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "System role cannot be modified, or caller lacks `roles:update`"},
        404: {"description": "Role not found"},
        422: {"description": "Validation error on the request body"},
    },
)
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


@app.get(
    "/auth/permissions",
    response_model=list[PermissionResponse],
    summary="List all permissions",
    description=(
        "Return the catalog of permission codenames known to the deployment "
        "(seeded by the active pack model). Requires the `permissions:list` "
        "permission."
    ),
    tags=["Permissions"],
    responses={
        200: {"description": "List of permissions"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `permissions:list`"},
    },
)
async def list_permissions(
    _user: User = Depends(require_permission("permissions:list")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Permission).order_by(Permission.codename))
    return [PermissionResponse.model_validate(p) for p in result.scalars().all()]


@app.post(
    "/auth/permissions/check",
    response_model=PermissionCheckResult,
    summary="Check a user's permission",
    description=(
        "Evaluate whether a given user holds a specific permission, "
        "optionally scoped to a resource (`resource_type` + `resource_id`). "
        "Checks role bindings, direct grants, and resource ownership. "
        "Requires the `permissions:check` permission."
    ),
    tags=["Permissions"],
    responses={
        200: {"description": "Permission check result"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `permissions:check`"},
        404: {"description": "Target user not found"},
        422: {"description": "Validation error on the request body"},
    },
)
async def check_user_permission(
    req: PermissionCheck,
    _admin: User = Depends(require_permission("permissions:check")),
    db: AsyncSession = Depends(get_db),
):
    from .permission_service import check_permission

    user_result = await db.execute(select(User).where(User.id == req.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    allowed = await check_permission(db, user, req.permission, req.resource_type, req.resource_id)
    return PermissionCheckResult(allowed=allowed, permission=req.permission, user_id=req.user_id)


# ── User Role Assignments (Phase 2) ──────────────


@app.get(
    "/auth/users/{user_id}/roles",
    response_model=list[UserRoleResponse],
    summary="List a user's role assignments",
    description=("Return every (role, tenant, scope) assignment for the given user. Admin only."),
    tags=["User Roles"],
    responses={
        200: {"description": "User's role assignments"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
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
    summary="Assign a role to a user",
    description=(
        "Create a new role assignment for the user, optionally scoped to a "
        "tenant and/or resource (`scope_type`, `scope_id`). Audit-logged "
        "with the granting admin's id. Admin only."
    ),
    tags=["User Roles"],
    responses={
        201: {"description": "Role assigned"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "User or role not found"},
        422: {"description": "Validation error on the request body"},
    },
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


@app.delete(
    "/auth/users/{user_id}/roles/{assignment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a role assignment from a user",
    description=(
        "Delete a specific role assignment by id, scoped to the given user. "
        "Audit-logged. Admin only."
    ),
    tags=["User Roles"],
    responses={
        204: {"description": "Assignment removed"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Assignment not found"},
    },
)
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


@app.get(
    "/auth/providers",
    response_model=list[ProviderResponse],
    summary="List identity providers",
    description=(
        "Return every configured OIDC/SAML identity provider, ordered by "
        "priority (highest first). Admin only."
    ),
    tags=["Identity Providers"],
    responses={
        200: {"description": "List of providers"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def list_providers(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(IdentityProvider).order_by(IdentityProvider.priority.desc()))
    return [ProviderResponse.model_validate(p) for p in result.scalars().all()]


_OIDC_OVERRIDE_KEYS = ("token_url", "userinfo_url", "jwks_url", "authorize_url")


async def _prefetch_oidc_discovery(provider_type: str, config: dict) -> None:
    """Eager-validate an OIDC provider's discovery doc on create/update.

    Catches misconfigured issuers at registration time rather than first
    login — operators get a 422 with the IdP error inline, vs. a single
    user hitting an opaque "Invalid ID token from IdP" weeks later.
    SAML providers skip this check (no discovery surface).

    If the operator has supplied every endpoint override
    (``token_url``, ``userinfo_url``, ``jwks_url``, ``authorize_url``)
    then the provider is fully self-described and the discovery probe is
    skipped — useful for private IdPs that don't publish a discovery
    document.
    """
    if provider_type != "oidc":
        return
    config = config or {}
    if all(config.get(key) for key in _OIDC_OVERRIDE_KEYS):
        return
    issuer = config.get("issuer")
    if not issuer:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="OIDC provider config must include 'issuer' or full endpoint overrides",
        )
    from .sso_service import discover_oidc_metadata

    await discover_oidc_metadata(issuer)


@app.post(
    "/auth/providers",
    response_model=ProviderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an identity provider",
    description=(
        "Register a new OIDC or SAML identity provider. The `slug` must be "
        "unique across providers and is used in `/auth/sso/{slug}/...` URLs. "
        "Admin only."
    ),
    tags=["Identity Providers"],
    responses={
        201: {"description": "Provider created"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        409: {"description": "Provider slug already exists"},
        422: {"description": "Validation error on the request body"},
    },
)
async def create_provider(
    req: ProviderCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(IdentityProvider).where(IdentityProvider.slug == req.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already exists")

    await _prefetch_oidc_discovery(req.type.value, req.config)

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


@app.get(
    "/auth/providers/{provider_id}",
    response_model=ProviderResponse,
    summary="Get an identity provider",
    description="Return a provider's full configuration (including secrets). Admin only.",
    tags=["Identity Providers"],
    responses={
        200: {"description": "Provider detail"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Provider not found"},
    },
)
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


@app.patch(
    "/auth/providers/{provider_id}",
    response_model=ProviderResponse,
    summary="Update an identity provider",
    description=(
        "Patch a provider's name, config, active flag, or priority. The slug "
        "and type are immutable. Admin only."
    ),
    tags=["Identity Providers"],
    responses={
        200: {"description": "Updated provider"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Provider not found"},
        422: {"description": "Validation error on the request body"},
    },
)
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

    if req.config is not None:
        await _prefetch_oidc_discovery(provider.type.value, req.config)

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


@app.delete(
    "/auth/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an identity provider",
    description=(
        "Permanently delete a provider and its claim mappings. Existing "
        "external-identity links are orphaned but preserved. Audit-logged. "
        "Admin only."
    ),
    tags=["Identity Providers"],
    responses={
        204: {"description": "Provider deleted"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Provider not found"},
    },
)
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


@app.get(
    "/auth/providers/{provider_id}/mappings",
    response_model=list[ClaimMappingResponse],
    summary="List a provider's claim→role mappings",
    description=(
        "Return every claim-to-role mapping configured for this provider, "
        "ordered by priority (highest first). Mappings drive automatic role "
        "assignment during SSO sign-in. Admin only."
    ),
    tags=["Claim Mappings"],
    responses={
        200: {"description": "List of claim mappings"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
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
    summary="Create a claim→role mapping",
    description=(
        "Define a rule that grants the named role when an SSO claim matches "
        "the supplied value (or regex pattern). Higher-priority mappings "
        "evaluate first. Admin only."
    ),
    tags=["Claim Mappings"],
    responses={
        201: {"description": "Mapping created"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Provider or role not found"},
        422: {"description": "Validation error on the request body"},
    },
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
    summary="Delete a claim mapping",
    description=("Remove a single claim→role rule for this provider. Audit-logged. Admin only."),
    tags=["Claim Mappings"],
    responses={
        204: {"description": "Mapping deleted"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Mapping not found"},
    },
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


# ── SSO Public Discovery & OIDC Flow ─────────────
#
# (Note: the Phase 3 placeholder route POST /auth/sso/callback was removed —
#  it accepted an unauthenticated JSON body containing arbitrary email +
#  claims and minted tokens via JIT. The canonical OIDC callback path is
#  POST /auth/sso/{slug}/token below, which exchanges the IdP code, verifies
#  the ID-token signature against the IdP's JWKS, validates iss/aud/exp/nonce,
#  and only then JIT-provisions and issues tokens. SAML support, when added,
#  must replicate that signature-verification posture before calling
#  jit_provision_user; do not reintroduce an unauthenticated "trust-the-body"
#  shortcut.)


@app.get(
    "/auth/sso/providers",
    summary="List public SSO providers",
    description=(
        "Return the public-facing list of active SSO providers (id, type, "
        "name, slug). Frontends call this from the login page to render the "
        'list of "Sign in with X" buttons. Public — no auth required.'
    ),
    tags=["SSO"],
    responses={200: {"description": "Public list of active SSO providers"}},
    openapi_extra={"security": []},
)
async def list_public_providers(db: AsyncSession = Depends(get_db)):
    """Public endpoint: returns active SSO providers for the login page."""
    result = await db.execute(
        select(IdentityProvider)
        .where(IdentityProvider.is_active == 1)
        .order_by(IdentityProvider.priority.desc())
    )
    return [
        {"id": p.id, "type": p.type.value, "name": p.name, "slug": p.slug}
        for p in result.scalars().all()
    ]


@app.get(
    "/auth/sso/{slug}/authorize",
    summary="Build SSO authorize URL",
    description=(
        "Return the IdP-specific authorization URL for the frontend to "
        "redirect to. Generates the `state` (CSRF) and `nonce` (OIDC replay) "
        "tokens. Public — no auth required."
    ),
    tags=["SSO"],
    responses={
        200: {"description": "Authorize URL plus opaque `state` for callback"},
        400: {"description": "Provider type is not supported"},
        404: {"description": "Provider not found or inactive"},
    },
    openapi_extra={"security": []},
)
async def sso_authorize(
    slug: str,
    redirect_uri: str,
    db: AsyncSession = Depends(get_db),
):
    """Build the IdP authorization URL for OIDC/SAML redirect.

    Persists the minted ``(state, nonce)`` pair so the callback can verify it
    is a state we minted, that it hasn't been used, and that the ID token's
    ``nonce`` claim matches.
    """
    from urllib.parse import urlencode

    from .sso_service import discover_oidc_metadata, store_sso_state

    result = await db.execute(
        select(IdentityProvider).where(
            IdentityProvider.slug == slug, IdentityProvider.is_active == 1
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    # Defense in depth on top of the IdP-side Redirect URL allowlist: when
    # AUTH_SSO_REDIRECT_BASE_URL is set, require the caller's redirect_uri
    # to be exactly {base}/sso/callback/{slug}. The IdP's allowlist is
    # authoritative; this check just refuses to mint state for callbacks
    # that we know are bound to fail at the IdP anyway, and tightens the
    # surface against open-redirect-style attacks if an operator
    # misconfigures the IdP's allowlist (e.g. wildcards a domain).
    base = settings.sso_redirect_base_url.rstrip("/") if settings.sso_redirect_base_url else ""
    if base:
        expected_redirect = f"{base}/sso/callback/{slug}"
        if redirect_uri != expected_redirect:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"redirect_uri must equal {expected_redirect}",
            )

    config = provider.config or {}
    state, nonce = await store_sso_state(db, provider_id=provider.id, redirect_uri=redirect_uri)

    if provider.type.value == "oidc":
        authorize_endpoint = config.get("authorize_url")
        if not authorize_endpoint:
            discovery = await discover_oidc_metadata(config.get("issuer", ""))
            authorize_endpoint = discovery.get("authorization_endpoint")
        if not authorize_endpoint:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="OIDC provider missing authorization_endpoint",
            )

        params = urlencode(
            {
                "client_id": config.get("client_id", ""),
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": config.get("scope", "openid email profile"),
                "state": state,
                "nonce": nonce,
            }
        )
        return {
            "authorize_url": f"{authorize_endpoint}?{params}",
            "state": state,
            "provider_slug": slug,
        }

    elif provider.type.value == "saml":
        login_url = config.get("login_url", "")
        return {
            "authorize_url": login_url,
            "state": state,
            "provider_slug": slug,
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unsupported provider type: {provider.type.value}",
    )


@app.post(
    "/auth/sso/{slug}/token",
    response_model=TokenResponse,
    summary="Exchange SSO code for internal tokens",
    description=(
        "Exchange the OIDC authorization `code` for a fresh internal "
        "access/refresh token pair. The auth-service performs the IdP token "
        "exchange server-side, JIT-provisions the user, applies claim→role "
        "mappings, and issues internal JWTs. Public — no auth required."
    ),
    tags=["SSO"],
    responses={
        200: {"description": "Token pair issued"},
        400: {"description": "Missing, expired, or unknown state"},
        401: {"description": "IdP ID-token verification failed (signature, nonce, claims)"},
        404: {"description": "Provider not found or inactive"},
    },
    openapi_extra={"security": []},
)
@limiter.limit(settings.rate_limit_sso_token)
async def sso_token_exchange(
    slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Exchange OIDC authorization code for internal JWT tokens.

    Requires the ``state`` minted at ``/authorize`` so the callback is
    cryptographically tied to a prior authorize call from the same client.
    The IdP's ID token is signature-verified against the IdP's JWKS and its
    ``nonce`` claim is matched against the one we persisted before the
    JIT-provisioning step runs.
    """
    body = await request.json()
    code = body.get("code", "")
    redirect_uri = body.get("redirect_uri", "")
    state = body.get("state", "")

    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_state", "error_description": "state parameter is required"},
        )

    result = await db.execute(
        select(IdentityProvider).where(
            IdentityProvider.slug == slug, IdentityProvider.is_active == 1
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    from .sso_service import (
        apply_claim_mappings,
        consume_sso_state,
        exchange_oidc_code,
        issue_sso_tokens,
        jit_provision_user,
        select_external_id,
    )

    # Single-use state consumption. The row is deleted whether or not the
    # downstream IdP exchange succeeds — a leaked state is useless after one
    # attempt, replay attempts return invalid_state.
    state_row = await consume_sso_state(db, state=state, provider_id=provider.id)

    # The redirect_uri presented at /token must match the one we minted state
    # against at /authorize. Refuses mid-flight redirect-URI substitution and
    # ensures the IdP's token-endpoint redirect_uri parameter (which OIDC
    # requires to equal the authorize-time value) matches what we stored.
    if redirect_uri != state_row.redirect_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_state", "error_description": "redirect_uri mismatch"},
        )

    user_info = await exchange_oidc_code(
        provider,
        code,
        redirect_uri,
        expected_nonce=state_row.nonce,
    )

    external_id = select_external_id(user_info)
    if not external_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="IdP claims missing a stable subject identifier (oid / user_id / sub)",
        )

    user, _created = await jit_provision_user(
        db,
        provider,
        external_id=external_id,
        email=user_info.get("email", ""),
        name=user_info.get("name", "SSO User"),
        raw_claims=user_info,
    )

    await apply_claim_mappings(db, provider, user, user_info)
    access_token, refresh_value = await issue_sso_tokens(db, user)
    return _build_token_response(access_token, refresh_value, user)


# ── Groups (Phase 4, admin) ───────────────────────


@app.get(
    "/auth/groups",
    summary="List groups",
    description=("Return every group (local or SCIM-provisioned) ordered by name. Admin only."),
    tags=["Groups"],
    responses={
        200: {"description": "List of groups"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def list_groups(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group

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


@app.post(
    "/auth/groups",
    status_code=status.HTTP_201_CREATED,
    summary="Create a group",
    description="Create a new local group. Audit-logged. Admin only.",
    tags=["Groups"],
    responses={
        201: {"description": "Group created"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        422: {"description": "Validation error on the request body"},
    },
)
async def create_group(
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group

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


@app.get(
    "/auth/groups/{group_id}/members",
    summary="List a group's members",
    description="Return every user belonging to the group. Admin only.",
    tags=["Groups"],
    responses={
        200: {"description": "List of member users"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def list_group_members(
    group_id: int,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import GroupMembership

    result = await db.execute(
        select(User)
        .join(GroupMembership, GroupMembership.user_id == User.id)
        .where(GroupMembership.group_id == group_id)
    )
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@app.post(
    "/auth/groups/{group_id}/members",
    status_code=status.HTTP_201_CREATED,
    summary="Add a member to a group",
    description=("Add the supplied `user_id` to the group's membership. Audit-logged. Admin only."),
    tags=["Groups"],
    responses={
        201: {"description": "Member added"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        422: {"description": "Validation error on the request body"},
    },
)
async def add_group_member(
    group_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import GroupMembership

    body = await request.json()
    user_id = body["user_id"]
    db.add(GroupMembership(group_id=group_id, user_id=user_id))
    await db.commit()
    await log_audit(db, admin.id, "add_group_member", f"group={group_id} user={user_id}")
    return {"group_id": group_id, "user_id": user_id}


@app.delete(
    "/auth/groups/{group_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member from a group",
    description="Remove the user from the group's membership. Admin only.",
    tags=["Groups"],
    responses={
        204: {"description": "Member removed"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Membership not found"},
    },
)
async def remove_group_member(
    group_id: int,
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import GroupMembership

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


@app.put(
    "/auth/groups/{group_id}/roles",
    summary="Set a group's roles",
    description=(
        "Replace the full role-id list bound to the group. Members of the "
        "group inherit every bound role. Audit-logged. Admin only."
    ),
    tags=["Groups"],
    responses={
        200: {"description": "Group roles updated"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def set_group_roles(
    group_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import GroupRole

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


@app.get(
    "/scim/v2/ServiceProviderConfig",
    summary="SCIM service-provider config",
    description=(
        "RFC 7643 §5: advertise SCIM 2.0 capabilities (patch, bulk, filter, "
        "etag, change-password, sort, auth schemes) supported by this server."
    ),
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM ServiceProviderConfig document"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
async def scim_service_provider_config(
    _token: str = Depends(scim_service.require_scim_auth),
):
    return scim_service.SCIM_SERVICE_PROVIDER_CONFIG


@app.get(
    "/scim/v2/Schemas",
    summary="SCIM schemas",
    description=(
        "RFC 7644 §4: return the SCIM 2.0 schema definitions supported by "
        "this server (User, Group, EnterpriseUser)."
    ),
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM schema catalog"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
async def scim_schemas(_token: str = Depends(scim_service.require_scim_auth)):
    return scim_service.SCIM_SCHEMAS


@app.get(
    "/scim/v2/ResourceTypes",
    summary="SCIM resource types",
    description=(
        "RFC 7644 §4: return the SCIM 2.0 resource types this server exposes (Users, Groups)."
    ),
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM resource-type catalog"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
async def scim_resource_types(_token: str = Depends(scim_service.require_scim_auth)):
    return scim_service.SCIM_RESOURCE_TYPES


@app.get(
    "/scim/v2/Users",
    summary="SCIM: list users",
    description=(
        "RFC 7644 §3.4.2: return all users wrapped in a SCIM ListResponse. "
        "Pagination, filtering, and sorting are not implemented in this "
        "release."
    ),
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM ListResponse of users"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
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


@app.post(
    "/scim/v2/Users",
    status_code=status.HTTP_201_CREATED,
    summary="SCIM: create user",
    description=(
        "RFC 7644 §3.3: provision a user from a SCIM User resource. Maps "
        "SCIM `userName`/`emails`/`active` into the local user model."
    ),
    tags=["SCIM"],
    responses={
        201: {"description": "User created and returned as SCIM resource"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
async def scim_create_user_endpoint(
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    data = await request.json()
    user = await scim_service.scim_create_user(db, data)
    return scim_service.user_to_scim(user)


@app.get(
    "/scim/v2/Users/{user_id}",
    summary="SCIM: get user",
    description="RFC 7644 §3.4.1: return a single user as a SCIM resource.",
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM User resource"},
        401: {"description": "SCIM bearer token missing or invalid"},
        404: {"description": "User not found"},
    },
)
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


@app.put(
    "/scim/v2/Users/{user_id}",
    summary="SCIM: replace user",
    description=(
        "RFC 7644 §3.5.1: full-resource replace of a SCIM User. Updates "
        "name, emails, and active flag from the request body."
    ),
    tags=["SCIM"],
    responses={
        200: {"description": "Updated SCIM User resource"},
        401: {"description": "SCIM bearer token missing or invalid"},
        404: {"description": "User not found"},
    },
)
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


@app.delete(
    "/scim/v2/Users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="SCIM: deprovision user",
    description=(
        "RFC 7644 §3.6: deprovision a user. Marks the user inactive (soft "
        "delete) and revokes every refresh token, forcing logout from all "
        "sessions."
    ),
    tags=["SCIM"],
    responses={
        204: {"description": "User deactivated and tokens revoked"},
        401: {"description": "SCIM bearer token missing or invalid"},
        404: {"description": "User not found"},
    },
)
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


@app.get(
    "/scim/v2/Groups",
    summary="SCIM: list groups",
    description="RFC 7644 §3.4.2: return all groups wrapped in a SCIM ListResponse.",
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM ListResponse of groups"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
async def scim_list_groups(
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group

    result = await db.execute(select(Group).order_by(Group.id))
    groups = result.scalars().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(groups),
        "Resources": [scim_service.group_to_scim(g) for g in groups],
    }


@app.post(
    "/scim/v2/Groups",
    status_code=status.HTTP_201_CREATED,
    summary="SCIM: create group",
    description=(
        "RFC 7644 §3.3: provision a group from a SCIM Group resource. "
        "Member references in the payload are resolved against local users."
    ),
    tags=["SCIM"],
    responses={
        201: {"description": "Group created and returned as SCIM resource"},
        401: {"description": "SCIM bearer token missing or invalid"},
    },
)
async def scim_create_group_endpoint(
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    data = await request.json()
    group = await scim_service.scim_create_group(db, data)
    return scim_service.group_to_scim(group)


@app.get(
    "/scim/v2/Groups/{group_id}",
    summary="SCIM: get group",
    description="RFC 7644 §3.4.1: return a single group as a SCIM resource.",
    tags=["SCIM"],
    responses={
        200: {"description": "SCIM Group resource"},
        401: {"description": "SCIM bearer token missing or invalid"},
        404: {"description": "Group not found"},
    },
)
async def scim_get_group(
    group_id: int,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return scim_service.group_to_scim(group)


@app.put(
    "/scim/v2/Groups/{group_id}",
    summary="SCIM: replace group",
    description=(
        "RFC 7644 §3.5.1: full-resource replace of a SCIM Group. Updates "
        "display name and member set."
    ),
    tags=["SCIM"],
    responses={
        200: {"description": "Updated SCIM Group resource"},
        401: {"description": "SCIM bearer token missing or invalid"},
        404: {"description": "Group not found"},
    },
)
async def scim_replace_group(
    group_id: int,
    request: Request,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    data = await request.json()
    group = await scim_service.scim_update_group(db, group, data)
    return scim_service.group_to_scim(group)


@app.delete(
    "/scim/v2/Groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="SCIM: delete group",
    description="RFC 7644 §3.6: permanently delete a SCIM group.",
    tags=["SCIM"],
    responses={
        204: {"description": "Group deleted"},
        401: {"description": "SCIM bearer token missing or invalid"},
        404: {"description": "Group not found"},
    },
)
async def scim_delete_group(
    group_id: int,
    _token: str = Depends(scim_service.require_scim_auth),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await db.delete(group)
    await db.commit()


# ── Audit (Phase 5) ──────────────────────────────


@app.get(
    "/auth/audit",
    summary="Query audit logs",
    description=(
        "Return audit events filtered by event_type, actor, target, and/or "
        "result. Supports `offset`/`limit` pagination (default limit=50). "
        "Requires the `admin.audit.view` permission."
    ),
    tags=["Audit"],
    responses={
        200: {"description": "Paginated audit log entries with total count"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `admin.audit.view`"},
    },
)
@limiter.limit(settings.rate_limit_audit)
async def query_audit(
    request: Request,
    _user: User = Depends(require_pack_permission("admin.audit.view")),
    db: AsyncSession = Depends(get_db),
):
    from .audit_service import audit_log_to_dict, query_audit_logs

    params = request.query_params
    logs, total = await query_audit_logs(
        db,
        event_type=params.get("event_type"),
        actor_user_id=int(params["actor_user_id"]) if params.get("actor_user_id") else None,
        target_type=params.get("target_type"),
        target_id=params.get("target_id"),
        result_filter=params.get("result"),
        offset=int(params.get("offset", 0)),
        limit=int(params.get("limit", 50)),
    )
    return {
        "items": [audit_log_to_dict(log) for log in logs],
        "total": total,
        "offset": int(params.get("offset", 0)),
        "limit": int(params.get("limit", 50)),
    }


@app.get(
    "/auth/audit/export",
    summary="Export audit logs",
    description=(
        "Return up to 10,000 audit events as a JSON array for offline "
        "analysis. Use NDJSON streaming for larger exports in production. "
        "Requires the `admin.audit.view` permission."
    ),
    tags=["Audit"],
    responses={
        200: {"description": "JSON array of audit events"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller lacks `admin.audit.view`"},
    },
)
@limiter.limit(settings.rate_limit_audit_export)
async def export_audit(
    request: Request,
    _user: User = Depends(require_pack_permission("admin.audit.view")),
    db: AsyncSession = Depends(get_db),
):
    """Export all audit logs as JSON array (for streaming, use NDJSON in production)."""
    from .audit_service import audit_log_to_dict, query_audit_logs

    logs, _ = await query_audit_logs(db, limit=10000)
    return [audit_log_to_dict(log) for log in logs]


@app.post(
    "/auth/audit/purge",
    summary="Purge old audit logs",
    description=(
        "Delete audit log entries older than `AUTH_AUDIT_RETENTION_DAYS`. "
        "Returns the number of rows deleted. The purge itself is audit-logged. "
        "Admin only."
    ),
    tags=["Audit"],
    responses={
        200: {"description": "Number of audit rows deleted"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def purge_audit(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .audit_service import purge_old_logs

    deleted = await purge_old_logs(db)
    await log_audit(db, admin.id, "purge_audit", f"deleted={deleted}")
    return {"deleted": deleted}


# ── Admin Dashboard (Phase 6) ────────────────────


@app.get(
    "/auth/admin/status",
    summary="Admin dashboard status",
    description=(
        "Return service version, active profile, feature flags, and rollup "
        "counts (total/active users, active sessions, identity providers, "
        "groups). Powers the admin dashboard landing tile. Admin only."
    ),
    tags=["Admin"],
    responses={
        200: {"description": "Status snapshot with feature flags + stats"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def admin_status(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    from .models import Group, IdentityProvider, RefreshToken

    user_count = await db.scalar(select(func.count()).select_from(User))
    active_users = await db.scalar(
        select(func.count()).select_from(User).where(User.is_active == 1)
    )
    active_sessions = await db.scalar(
        select(func.count()).select_from(RefreshToken).where(RefreshToken.revoked == 0)
    )
    provider_count = await db.scalar(select(func.count()).select_from(IdentityProvider))
    group_count = await db.scalar(select(func.count()).select_from(Group))

    return {
        "version": __version__,
        "profile": settings.profile,
        "features": {
            "local_auth": settings.local_auth_enabled,
            "oidc": settings.oidc_enabled,
            "saml": settings.saml_enabled,
            "scim": settings.scim_enabled,
            "audit": settings.audit_enabled,
        },
        "stats": {
            "total_users": user_count,
            "active_users": active_users,
            "active_sessions": active_sessions,
            "identity_providers": provider_count,
            "groups": group_count,
        },
    }


# ── OAuth2 / Service Accounts (Spec 002) ─────────


def _oauth2_error(
    error: str,
    description: str,
    *,
    http_status: int = status.HTTP_400_BAD_REQUEST,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build an RFC 6749 §5.2-shaped error response.

    Callers return the response directly — raising HTTPException would bury
    the OAuth2 error fields under the FastAPI ``{"detail": ...}`` envelope
    that integrators don't expect on the token endpoint. RFC 6749 §5.1 also
    requires the no-store / no-cache header pair on any response from a
    token-issuing endpoint that *could* contain credentials, so the helper
    stamps them unconditionally — including on every error variant.
    """
    body: dict[str, str] = {"error": error, "error_description": description}
    response_headers: dict[str, str] = {
        "Cache-Control": _NO_STORE_CACHE,
        "Pragma": _NO_CACHE_PRAGMA,
    }
    if headers:
        response_headers.update(headers)
    return JSONResponse(status_code=http_status, content=body, headers=response_headers)


def _parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    """Decode an HTTP Basic ``Authorization: Basic ...`` header.

    Returns ``(client_id, client_secret)`` on success or ``None`` when the
    header is absent or malformed. The token endpoint translates ``None`` plus
    missing form credentials into ``invalid_client`` — never raise here.
    """
    if not header:
        return None
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if ":" not in decoded:
        return None
    client_id, _, client_secret = decoded.partition(":")
    return client_id, client_secret


def _invalid_client_response(*, attempted_basic_auth: bool) -> JSONResponse:
    """Return the RFC 6749 §5.2 invalid_client 401 with a correct challenge.

    RFC 7235 §2.1 reserves ``WWW-Authenticate`` for declaring *attempted* auth
    schemes; if the caller used form-body credentials, no HTTP auth scheme was
    in play so emitting ``WWW-Authenticate: Basic`` would be a lie that some
    HTTP clients translate into prompting the user for a Basic-auth username
    and password. Emit it only when the caller actually tried Basic.
    """
    headers: dict[str, str] | None = None
    if attempted_basic_auth:
        headers = {"WWW-Authenticate": 'Basic realm="auth-service", error="invalid_client"'}
    return _oauth2_error(
        OAUTH2_ERROR_INVALID_CLIENT,
        "Client authentication failed",
        http_status=status.HTTP_401_UNAUTHORIZED,
        headers=headers,
    )


def _is_form_urlencoded(content_type: str | None) -> bool:
    """RFC 6749 §3.2: token endpoint accepts only ``application/x-www-form-urlencoded``.

    Allows the standard parameter suffix (``; charset=utf-8`` etc.) and is
    case-insensitive per RFC 7231.
    """
    if not content_type:
        return False
    base = content_type.split(";", 1)[0].strip().lower()
    return base == "application/x-www-form-urlencoded"


@app.post(
    "/auth/oauth/token",
    summary="OAuth2 token endpoint (client_credentials grant)",
    description=(
        "RFC 6749 §4.4 client_credentials grant. Issues an RS256 access token "
        "for an authenticated service account. Credentials may be supplied "
        "via HTTP Basic auth OR the form body — providing both returns "
        "`invalid_request`. The path lives under `/auth/` because the auth-"
        "service is reachable only through the pack frontend's `/auth/*` "
        "ingress prefix. Public — no existing bearer token required."
    ),
    tags=["OAuth2"],
    responses={
        200: {"description": "Access token issued"},
        400: {
            "description": (
                "Malformed request, unsupported grant (including when the master "
                "switch is off), or invalid scope"
            ),
        },
        401: {"description": "Invalid or unauthorized client credentials"},
        429: {"description": "Token endpoint rate limit exceeded"},
    },
    openapi_extra={"security": []},
)
@limiter.limit(settings.rate_limit_oauth_token)
async def oauth_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # RFC 6749 §3.2: the token endpoint MUST require
    # ``application/x-www-form-urlencoded`` — reject anything else before
    # parsing the form so a JSON-bodied request can't slip past as an empty
    # grant_type and bubble up as a generic 422.
    if not _is_form_urlencoded(request.headers.get("content-type")):
        return _oauth2_error(
            OAUTH2_ERROR_INVALID_REQUEST,
            "Content-Type must be application/x-www-form-urlencoded",
        )

    form = await request.form()
    grant_type = form.get("grant_type")
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    scope = form.get("scope")

    if not grant_type:
        return _oauth2_error(
            OAUTH2_ERROR_INVALID_REQUEST,
            "grant_type parameter is required",
        )

    if not settings.client_credentials_enabled:
        # RFC 6749 §5.2 maps ``unsupported_grant_type`` to HTTP 400. 503
        # implied "transient" — but the master switch is an intentional ops
        # decision, so the 400 path is the standards-compliant choice.
        return _oauth2_error(
            OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE,
            "client_credentials grant is disabled",
        )

    if grant_type != "client_credentials":
        return _oauth2_error(
            OAUTH2_ERROR_UNSUPPORTED_GRANT_TYPE,
            "Only client_credentials is supported",
        )

    basic_credentials = _parse_basic_auth(request.headers.get("authorization"))
    form_has_credentials = client_id is not None or client_secret is not None
    attempted_basic_auth = request.headers.get("authorization", "").lower().startswith("basic ")

    if basic_credentials is not None and form_has_credentials:
        # Per RFC 6749 §2.3.1, clients MUST NOT use more than one
        # authentication method in each request.
        return _oauth2_error(
            OAUTH2_ERROR_INVALID_REQUEST,
            "Use either HTTP Basic or form-body credentials, not both",
        )

    if basic_credentials is not None:
        presented_client_id, presented_client_secret = basic_credentials
    else:
        presented_client_id = client_id or ""
        presented_client_secret = client_secret or ""

    # Same response shape for every credential failure to prevent enumeration.
    invalid_client_response = _invalid_client_response(attempted_basic_auth=attempted_basic_auth)

    if not presented_client_id or not presented_client_secret:
        # Pay the bcrypt cost even on missing credentials so the response time
        # is indistinguishable from an unknown-client lookup (timing parity
        # with the verify_secret branch below).
        clients.verify_secret(presented_client_secret, clients.get_dummy_bcrypt_hash())
        return invalid_client_response

    account = await clients.get_client_by_client_id(db, presented_client_id)
    if account is None:
        # Pay the bcrypt cost on the unknown-client branch — otherwise an
        # attacker can time-correlate the response and enumerate valid
        # client_ids (~250ms parity gap at bcrypt rounds=12).
        clients.verify_secret(presented_client_secret, clients.get_dummy_bcrypt_hash())
        return invalid_client_response
    if not clients.verify_secret(presented_client_secret, account.client_secret_hash):
        return invalid_client_response
    if not clients.is_client_usable(account):
        return invalid_client_response

    allowed_scopes = clients.deserialize_scopes(account.scopes)
    requested_scopes = parse_scope_string(scope)
    try:
        issued_scopes = grant_scopes(
            allowed_scopes, requested_scopes, strict=settings.strict_scopes
        )
    except InvalidScopeError as exc:
        await log_audit(
            db,
            None,
            "oauth_token_invalid_scope",
            scope or "",
            principal_type=PrincipalType.client,
            principal_id=account.client_id,
            result=AuditResult.failure,
        )
        return _oauth2_error(OAUTH2_ERROR_INVALID_SCOPE, str(exc))

    token = await create_client_access_token(db, account, issued_scopes)
    ip = request.client.host if request.client else None
    await clients.update_last_used(db, account.client_id, ip)
    await log_audit(
        db,
        None,
        "oauth_token_issued",
        f"client={account.client_id}",
        principal_type=PrincipalType.client,
        principal_id=account.client_id,
    )

    return JSONResponse(
        content={
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": settings.client_token_expire_minutes * 60,
            "scope": " ".join(issued_scopes),
        },
        headers={"Cache-Control": _NO_STORE_CACHE, "Pragma": _NO_CACHE_PRAGMA},
    )


def _service_account_response(account: ServiceAccount) -> ServiceAccountResponse:
    return ServiceAccountResponse.model_validate(clients.service_account_to_dict(account))


def _service_account_with_secret(
    account: ServiceAccount, plaintext: str
) -> ServiceAccountWithSecret:
    return ServiceAccountWithSecret.model_validate(
        clients.service_account_to_dict(account, plaintext=plaintext)
    )


def require_client_credentials_enabled() -> None:
    """Block admin CRUD when ``AUTH_CLIENT_CREDENTIALS_ENABLED=false``.

    Spec 002 promises that the master switch turns the feature off "entirely"
    — gating only the token endpoint would let admins keep registering
    accounts that no one can ever exchange for a token. 503 here matches the
    pre-fix token-endpoint code: this is admin surface (not RFC-shaped), so
    a transient-style 503 is the more honest signal.
    """
    if not settings.client_credentials_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="client_credentials grant is disabled (AUTH_CLIENT_CREDENTIALS_ENABLED=false)",
        )


@app.post(
    "/auth/admin/clients",
    status_code=status.HTTP_201_CREATED,
    response_model=ServiceAccountWithSecret,
    summary="Create a service account",
    description=(
        "Register a new OAuth2 client_credentials principal owned by the "
        "calling admin. The response includes a one-time-visible "
        "`client_secret` — store it now, the server can't show it again. "
        "Admin only."
    ),
    tags=["Service Accounts"],
    responses={
        201: {"description": "Service account created with one-time-visible secret"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        409: {"description": "Per-owner client limit reached"},
        422: {"description": "Validation error on the request body"},
        503: {"description": "Client-credentials grant disabled (master switch off)"},
    },
)
async def create_service_account_endpoint(
    req: ServiceAccountCreate,
    response: Response,
    admin: User = Depends(require_admin),
    _master_switch: None = Depends(require_client_credentials_enabled),
    db: AsyncSession = Depends(get_db),
) -> ServiceAccountWithSecret:
    _apply_no_store(response)
    existing = await clients.count_clients_for_owner(db, admin.id)
    if existing >= settings.client_max_per_owner:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Per-owner client limit reached ({settings.client_max_per_owner})",
        )

    account, plaintext = await clients.create_client(
        db,
        owner_id=admin.id,
        name=req.name,
        description=req.description,
        scopes=req.scopes,
        expires_at=req.expires_at,
    )
    await log_audit(db, admin.id, "create_service_account", f"client={account.client_id}")
    return _service_account_with_secret(account, plaintext)


@app.get(
    "/auth/admin/clients",
    response_model=list[ServiceAccountResponse],
    summary="List service accounts",
    description=(
        "Admin sees every service account across all owners; non-admin "
        "callers see only their own. Both views are newest first. Admin only."
    ),
    tags=["Service Accounts"],
    responses={
        200: {"description": "List of service accounts (secrets never included)"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        503: {"description": "Client-credentials grant disabled (master switch off)"},
    },
)
async def list_service_accounts_endpoint(
    _admin: User = Depends(require_admin),
    _master_switch: None = Depends(require_client_credentials_enabled),
    db: AsyncSession = Depends(get_db),
) -> list[ServiceAccountResponse]:
    accounts = await clients.list_all_clients(db)
    return [_service_account_response(a) for a in accounts]


@app.get(
    "/auth/admin/clients/{client_pk}",
    response_model=ServiceAccountResponse,
    summary="Get a service account",
    description="Return a service account by primary key. Secret is never included. Admin only.",
    tags=["Service Accounts"],
    responses={
        200: {"description": "Service account detail"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Service account not found"},
        503: {"description": "Client-credentials grant disabled (master switch off)"},
    },
)
async def get_service_account_endpoint(
    client_pk: int,
    _admin: User = Depends(require_admin),
    _master_switch: None = Depends(require_client_credentials_enabled),
    db: AsyncSession = Depends(get_db),
) -> ServiceAccountResponse:
    account = await clients.get_client_by_id(db, client_pk)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found"
        )
    return _service_account_response(account)


@app.patch(
    "/auth/admin/clients/{client_pk}",
    response_model=ServiceAccountResponse,
    summary="Update a service account",
    description=(
        "Patch a service account's name, description, scopes, expiry, or "
        "active flag. Setting `is_active=false` stamps `revoked_at` if it "
        "wasn't already set. Audit-logged. Admin only."
    ),
    tags=["Service Accounts"],
    responses={
        200: {"description": "Updated service account"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Service account not found"},
        422: {"description": "Validation error on the request body"},
        503: {"description": "Client-credentials grant disabled (master switch off)"},
    },
)
async def update_service_account_endpoint(
    client_pk: int,
    req: ServiceAccountUpdate,
    admin: User = Depends(require_admin),
    _master_switch: None = Depends(require_client_credentials_enabled),
    db: AsyncSession = Depends(get_db),
) -> ServiceAccountResponse:
    # Pydantic ``model_fields_set`` distinguishes "field omitted" from
    # "field explicitly set to None" so the sentinel-based update_client can
    # clear nullable columns when the admin sends an explicit ``null``.
    sent = req.model_fields_set
    kwargs: dict[str, Any] = {}
    if "name" in sent:
        kwargs["name"] = req.name
    if "description" in sent:
        kwargs["description"] = req.description
    if "scopes" in sent:
        kwargs["scopes"] = req.scopes
    if "expires_at" in sent:
        kwargs["expires_at"] = req.expires_at
    if "is_active" in sent:
        kwargs["is_active"] = req.is_active

    account = await clients.update_client(db, client_pk, **kwargs)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found"
        )
    await log_audit(db, admin.id, "update_service_account", f"client={account.client_id}")
    return _service_account_response(account)


@app.post(
    "/auth/admin/clients/{client_pk}/rotate-secret",
    response_model=ServiceAccountWithSecret,
    summary="Rotate a service account's secret",
    description=(
        "Mint a new client_secret and return it once. The previous secret "
        "stops working immediately; the client_id stays the same so "
        "consumers only need to update one value. Audit-logged. Admin only."
    ),
    tags=["Service Accounts"],
    responses={
        200: {"description": "New one-time-visible client_secret"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Service account not found"},
        503: {"description": "Client-credentials grant disabled (master switch off)"},
    },
)
async def rotate_service_account_secret_endpoint(
    client_pk: int,
    response: Response,
    admin: User = Depends(require_admin),
    _master_switch: None = Depends(require_client_credentials_enabled),
    db: AsyncSession = Depends(get_db),
) -> ServiceAccountWithSecret:
    _apply_no_store(response)
    rotated = await clients.rotate_secret(db, client_pk)
    if rotated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found"
        )
    account, plaintext = rotated
    await log_audit(db, admin.id, "rotate_service_account", f"client={account.client_id}")
    return _service_account_with_secret(account, plaintext)


@app.delete(
    "/auth/admin/clients/{client_pk}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a service account",
    description=(
        "Soft-delete: sets `is_active=false` and stamps `revoked_at`. The "
        "row remains for audit attribution. Audit-logged. Admin only."
    ),
    tags=["Service Accounts"],
    responses={
        204: {"description": "Service account revoked"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Service account not found"},
        503: {"description": "Client-credentials grant disabled (master switch off)"},
    },
)
async def revoke_service_account_endpoint(
    client_pk: int,
    admin: User = Depends(require_admin),
    _master_switch: None = Depends(require_client_credentials_enabled),
    db: AsyncSession = Depends(get_db),
) -> None:
    account = await clients.revoke_client(db, client_pk)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found"
        )
    await log_audit(db, admin.id, "revoke_service_account", f"client={account.client_id}")


# ── Signing Keys (admin) ─────────────────────────


def _signing_key_to_dict(key: SigningKey) -> dict[str, Any]:
    return {
        "id": key.id,
        "kid": key.kid,
        "algorithm": key.algorithm,
        "status": str(key.status),
        "created_at": key.created_at.isoformat() if key.created_at else None,
        "rotated_at": key.rotated_at.isoformat() if key.rotated_at else None,
        "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
    }


@app.get(
    "/auth/admin/signing-keys",
    summary="List signing keys",
    description=(
        "Return every signing key with its kid, algorithm, status, and lifecycle "
        "timestamps. Private key material is never returned. Admin only."
    ),
    tags=["Signing Keys"],
    responses={
        200: {"description": "List of signing keys"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def list_signing_keys(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    result = await db.execute(select(SigningKey).order_by(SigningKey.created_at.desc()))
    return [_signing_key_to_dict(k) for k in result.scalars().all()]


@app.post(
    "/auth/admin/signing-keys/rotate",
    summary="Rotate the active signing key",
    description=(
        "Mint a new RS256 keypair, mark the current active key as "
        "`rotating_out` (kept in the JWKS for a 24h grace window so in-flight "
        "tokens stay verifiable), and start signing new tokens with the new "
        "key. Audit-logged. Admin only."
    ),
    tags=["Signing Keys"],
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "New active key minted"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
    },
)
async def rotate_signing_key(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    new_key = await rotate_active_key(db)
    await log_audit(db, admin.id, "rotate_signing_key", f"kid={new_key.kid}")
    return _signing_key_to_dict(new_key)


@app.delete(
    "/auth/admin/signing-keys/{kid}",
    summary="Revoke a signing key",
    description=(
        "Mark the signing key with the given `kid` as `revoked`. Tokens "
        "signed with that kid stop validating immediately and the key is "
        "removed from the public JWKS on the next fetch. Audit-logged. "
        "Admin only."
    ),
    tags=["Signing Keys"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {"description": "Key revoked"},
        401: {"description": "Token missing or invalid"},
        403: {"description": "Caller is not an admin"},
        404: {"description": "Signing key not found"},
    },
)
async def delete_signing_key(
    kid: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    revoked = await revoke_key(db, kid)
    if revoked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signing key not found")
    await log_audit(db, admin.id, "revoke_signing_key", f"kid={kid}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)  # noqa: S104
