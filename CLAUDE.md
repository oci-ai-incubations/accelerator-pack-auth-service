# CLAUDE.md — Enterprise Auth Service v1.0.0

## Overview

Enterprise-grade authentication and authorization service for OCI AI Accelerator packs. Provides JWT auth, fine-grained RBAC, OIDC/SAML SSO, SCIM 2.0 provisioning, audit logging, and multi-database support.

## Quick Start

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=. --cov-fail-under=80
ruff check . && ruff format --check .
pip-audit -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

## Architecture

Flat-file monolith with feature flags. All features in one process — disable unused capabilities via config.

| File | Purpose |
|------|---------|
| `main.py` | FastAPI app, all routes, middleware |
| `auth.py` | JWT, password hashing, dependencies (get_current_user, require_admin, require_permission) |
| `config.py` | Pydantic Settings with AUTH_ prefix, profile presets |
| `models.py` | SQLAlchemy ORM models (all tables) |
| `schemas.py` | Pydantic v2 request/response schemas |
| `database.py` | Engine factory (SQLite/PostgreSQL/Oracle 26ai) |
| `permission_service.py` | RBAC evaluation engine, role/permission seeding |
| `sso_service.py` | JIT provisioning, claim-to-role mapping, token bridge |
| `scim_service.py` | SCIM 2.0 user/group provisioning |
| `audit_service.py` | Structured audit logging, query, export, retention |

## Configuration

All settings via `AUTH_` env prefix. Use `AUTH_PROFILE` for presets:

| Profile | local_auth | oidc | saml | scim | audit |
|---------|-----------|------|------|------|-------|
| minimal | true | false | false | false | false |
| standard | true | true | false | false | true |
| enterprise | true | true | true | true | true |
| custom | (manual) | (manual) | (manual) | (manual) | (manual) |

Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PACK` | `base` | Active pack auth model (see Pack-extensible RBAC below). Known: `base`, `cuopt`, `paas_rag`, `vss`, `warehouse_pick_path`, `dox_pack`. |
| `AUTH_DATABASE_URL` | `sqlite+aiosqlite:///./auth.db` | Database URL |
| `AUTH_JWT_SECRET` | `change-me-in-production` | JWT signing secret |
| `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token TTL |
| `AUTH_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL |
| `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` | `5` | Failed logins before lockout |
| `AUTH_MAX_CONCURRENT_SESSIONS` | `5` | Max refresh tokens per user |
| `AUTH_CORS_ORIGINS` | `*` | Comma-separated CORS origins |
| `AUTH_SCIM_TOKEN` | `` | SHA256 hash of SCIM bearer token |
| `AUTH_AUDIT_RETENTION_DAYS` | `90` | Days before audit log purge |
| `AUTH_PROFILE` | `custom` | Feature profile preset |

## API Endpoints

### Health
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/health` | No | Readiness check |
| GET | `/auth/alive` | No | Liveness check |

### Authentication
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | No | Register (guarded by local_auth) |
| POST | `/auth/login` | No | Login (guarded by local_auth) |
| POST | `/auth/refresh` | No | Refresh access token |
| POST | `/auth/logout` | Yes | Revoke all tokens + blacklist |
| POST | `/auth/token/revoke` | Yes | Blacklist specific token |
| GET | `/auth/me` | Yes | Current user |

### User Management
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/users` | Admin | List users |
| PATCH | `/auth/users/{id}` | Admin | Update user |
| GET | `/auth/users/{id}/roles` | Admin | User's role assignments |
| POST | `/auth/users/{id}/roles` | Admin | Assign role |
| DELETE | `/auth/users/{id}/roles/{aid}` | Admin | Remove role |

### Collections (Legacy)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/collections/{cid}/permissions` | Admin | Assign |
| DELETE | `/auth/collections/{cid}/permissions/{uid}` | Admin | Revoke |
| GET | `/auth/collections/{cid}/permissions` | Admin | List |
| GET | `/auth/collections/my-access` | Yes | My access |

### Roles & Permissions (Phase 2)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET/POST | `/auth/roles` | roles:list/create | CRUD |
| GET/PATCH/DELETE | `/auth/roles/{id}` | roles:read/update/delete | CRUD |
| PUT | `/auth/roles/{id}/permissions` | roles:update | Set permissions |
| GET | `/auth/permissions` | permissions:list | List all |
| POST | `/auth/permissions/check` | permissions:check | Check permission |

### Identity Providers (Phase 3)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET/POST | `/auth/providers` | Admin | CRUD |
| GET/PATCH/DELETE | `/auth/providers/{id}` | Admin | CRUD |
| GET/POST | `/auth/providers/{id}/mappings` | Admin | Claim mappings |
| DELETE | `/auth/providers/{id}/mappings/{mid}` | Admin | Delete mapping |
| GET | `/auth/sso/providers` | No | List public SSO providers |
| GET | `/auth/sso/{slug}/authorize` | No | Build IdP authorize URL + state |
| POST | `/auth/sso/{slug}/token` | No | Exchange IdP auth code for internal tokens |

### Groups (Phase 4)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET/POST | `/auth/groups` | Admin | CRUD |
| GET/POST/DELETE | `/auth/groups/{id}/members[/{uid}]` | Admin | Members |
| PUT | `/auth/groups/{id}/roles` | Admin | Group-role sync |

### SCIM 2.0 (Phase 4)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/scim/v2/ServiceProviderConfig` | SCIM | Capabilities |
| GET | `/scim/v2/Schemas` | SCIM | Schema discovery |
| GET | `/scim/v2/ResourceTypes` | SCIM | Resource types |
| CRUD | `/scim/v2/Users[/{id}]` | SCIM | User provisioning |
| CRUD | `/scim/v2/Groups[/{id}]` | SCIM | Group provisioning |

### Audit (Phase 5)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/audit` | Admin | Query (filtered, paginated) |
| GET | `/auth/audit/export` | Admin | Export JSON |
| POST | `/auth/audit/purge` | Admin | Retention purge |

### Admin Dashboard (Phase 6)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/admin/status` | Admin | System status + stats |

## Database

Supports SQLite (dev), PostgreSQL, Oracle 26ai via `AUTH_DATABASE_URL` / `AUTH_DATABASE_TYPE`.

Alembic migrations: `001` through `006`. Tables: users, collection_permissions, refresh_tokens, token_blacklist, failed_login_attempts, tenants, roles, permissions, role_permissions, user_roles, direct_grants, resource_ownership, identity_providers, external_identities, claim_role_mappings, groups, group_memberships, group_roles, audit_logs.

### Schema bootstrap

At startup the FastAPI lifespan runs **`alembic upgrade head`** (via `database.init_db()`, which dispatches the synchronous alembic command to a worker thread). The previous implementation used `Base.metadata.create_all()`, which is a no-op against pre-existing tables and produced silent schema drift on upgrades — concretely, an old image without `sa.Identity` left Oracle USERS without an identity column, then a new image with `sa.Identity` in the models failed registrations with `ORA-01400: cannot insert NULL into USERS.ID`. Alembic now runs against the **runtime** database (Oracle / Postgres / SQLite — whatever `database._build_engine()` would pick) because `alembic/env.py` reads `AUTH_DATABASE_TYPE` + `AUTH_DATABASE_URL` / `AUTH_ORACLE_*` from `settings`. The `sqlalchemy.url` in `alembic.ini` is therefore ignored at runtime; it remains in the file only for offline-mode CLI invocations.

## Pack-extensible RBAC

Each accelerator pack ships its own `PackAuthModel` in `src/accelerator_pack_auth_service/pack_models/<pack>.py`. The active model — selected by `AUTH_PACK` env var — supplies the roles + permissions seeded on first deploy. Runtime CRUD via `/auth/roles` and `/auth/permissions` keeps working on top.

Active model contract (see `pack_models/base.py`):

```python
class PackAuthModel(BaseModel):
    pack_id: str
    roles: list[str]
    permissions: list[str]
    role_permissions: dict[str, list[str]]  # role → list of perm keys OR ["*"]
```

Built-in models:

| AUTH_PACK | Roles | Notes |
|-----------|-------|-------|
| `base` (default) | admin, user | Minimal — admin + user only, two perms (admin.users.manage, admin.audit.view) |
| `cuopt` | admin, user, reader | VRP-shaped perms (cuopt.solve, cuopt.view, chat.use, weather.view, config.read, admin.*) |
| `paas_rag` | admin, user, reader, pending | Historical collection-based RBAC (collections:read/write/manage/delete, etc.) |
| `vss`, `warehouse_pick_path`, `dox_pack` | admin, user | Stubs — fill in pack-specific perms later |

**Adding a new pack:**

1. Create `pack_models/<pack>.py` exporting `<PACK>_MODEL: PackAuthModel`.
2. Register it in `pack_models/registry.py:PACK_MODELS`.
3. Add tests in `tests/test_pack_models.py` (validity) and optionally `tests/test_pack_seeding.py`.
4. Deploy with `AUTH_PACK=<pack>`.

**Behavior change vs. pre-pack-model deploys (paas_rag):**

Existing paas_rag deploys MUST set `AUTH_PACK=paas_rag` after upgrading past this change. Without it, `AUTH_PACK` defaults to `base` and only `admin` + `user` roles are seeded — the `reader` + `pending` roles and the collection-based permissions disappear. The TF blueprint in `ai-accelerator-starter-packs` should plumb this from `var.starter_pack_category` into the auth-service recipe's `recipe_container_env`.

**Public endpoint** `GET /auth/pack/model` returns the active model — frontends call it to render only the admin tabs relevant to the deployment.

**Two permission dependencies** in `auth.py`:

- `require_permission(codename)` — full RBAC check via DB (role permissions, direct grants, resource ownership). Use for resource- or grant-scoped checks.
- `require_pack_permission(codename)` — static check against the active pack model's role→perm map. Faster, no DB. Use for pack-static permissions. Admin bypass matches legacy behavior.
