# Enterprise Auth Service

Enterprise-grade authentication and authorization microservice for OCI AI Accelerator packs. Built with FastAPI and SQLAlchemy, the service provides a complete identity layer that scales from single-developer SQLite deployments to production Oracle 26ai clusters. It supports local username/password authentication, federated login via OIDC and SAML, fine-grained role-based access control, SCIM 2.0 directory provisioning, structured audit logging, and configurable feature profiles that let you enable only what you need.

## Key Features

- **JWT Authentication** -- Access and refresh token pairs with automatic rotation, token blacklisting, account lockout, and concurrent session limits.
- **Fine-Grained RBAC** -- Roles, permissions, direct grants, and resource ownership evaluated in a deterministic priority order.
- **OIDC and SAML SSO** -- Federated login with Just-In-Time user provisioning, account linking, and claim-to-role mapping (exact match or regex).
- **SCIM 2.0 Provisioning** -- RFC 7644 compliant user and group lifecycle management for directory sync from Okta, Entra ID, OneLogin, and others.
- **Audit Logging** -- Structured event records with query, export, and configurable retention policies.
- **Multi-Database Support** -- SQLite for development, PostgreSQL for staging, Oracle 26ai for production. Auto-detected from connection configuration.
- **Configuration Profiles** -- Preset profiles (minimal, standard, enterprise) toggle feature flags in one variable, with full override via individual environment variables.

## Quick Start

### Install dependencies

```bash
pip install -r requirements.txt
```

### Set required environment variables

```bash
export AUTH_JWT_SECRET="your-secure-secret-here"
export AUTH_DATABASE_URL="sqlite+aiosqlite:///./auth.db"
```

### Run the service

```bash
uvicorn accelerator_pack_auth_service.main:app --host 0.0.0.0 --port 8080 --reload
```

The first user to register is automatically promoted to admin (controlled by `AUTH_AUTO_ADMIN_FIRST_USER`).

### Verify the service is running

```bash
curl http://localhost:8080/auth/health
# {"status": "healthy", "service": "auth", "version": "1.0.0"}
```

## Configuration

All settings use the `AUTH_` environment variable prefix. Use `AUTH_PROFILE` to apply a preset, then override individual flags as needed.

### Profile Presets

| Profile | Local Auth | OIDC | SAML | SCIM | Audit |
|------------|------------|------|------|------|-------|
| `minimal` | true | false | false | false | false |
| `standard` | true | true | false | false | true |
| `enterprise`| true | true | true | true | true |
| `custom` | (manual) | (manual) | (manual) | (manual) | (manual) |

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PROFILE` | `custom` | Feature profile preset |
| `AUTH_DATABASE_URL` | `sqlite+aiosqlite:///./auth.db` | Database connection URL |
| `AUTH_DATABASE_TYPE` | `auto` | Force database type: `auto`, `sqlite`, `postgres`, `oracle` |
| `AUTH_JWT_SECRET` | `change-me-in-production` | JWT signing secret |
| `AUTH_JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token TTL in minutes |
| `AUTH_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL in days |
| `AUTH_BCRYPT_ROUNDS` | `12` | bcrypt cost factor |
| `AUTH_CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `AUTH_RATE_LIMIT_LOGIN` | `10/minute` | Login endpoint rate limit |
| `AUTH_RATE_LIMIT_REGISTER` | `5/minute` | Registration endpoint rate limit |
| `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` | `5` | Failed logins before lockout |
| `AUTH_ACCOUNT_LOCKOUT_DURATION_MINUTES` | `30` | Lockout window in minutes |
| `AUTH_MAX_CONCURRENT_SESSIONS` | `5` | Maximum active refresh tokens per user |
| `AUTH_SCIM_ENABLED` | `false` | Enable SCIM 2.0 endpoints |
| `AUTH_SCIM_TOKEN` | (empty) | SHA-256 hash of SCIM bearer token |
| `AUTH_AUDIT_ENABLED` | `true` | Enable audit logging |
| `AUTH_AUDIT_RETENTION_DAYS` | `90` | Days before audit log purge |
| `AUTH_AUTO_ADMIN_FIRST_USER` | `true` | Promote first registered user to admin |

See [docs/configuration.md](docs/configuration.md) for the complete reference.

## Deployment

### Docker

```bash
docker build -t auth-service:latest .
docker run -p 8080:8080 \
  -e AUTH_JWT_SECRET="production-secret" \
  -e AUTH_DATABASE_URL="postgresql+asyncpg://user:pass@db:5432/auth" \
  -e AUTH_PROFILE="enterprise" \
  auth-service:latest
```

### Kubernetes (basic deployment)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
        - name: auth-service
          image: auth-service:latest
          ports:
            - containerPort: 8080
          env:
            - name: AUTH_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: jwt-secret
            - name: AUTH_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: database-url
            - name: AUTH_PROFILE
              value: "enterprise"
          livenessProbe:
            httpGet:
              path: /auth/alive
              port: 8080
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /auth/health
              port: 8080
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
spec:
  selector:
    app: auth-service
  ports:
    - port: 8080
      targetPort: 8080
```

## Documentation

Detailed guides are available in the `docs/` directory:

- [Architecture](docs/architecture.md) -- System design, authentication and authorization flows, deployment topology
- [API Reference](docs/api-reference.md) -- Complete endpoint reference with request/response examples
- [Configuration](docs/configuration.md) -- Full environment variable reference, profiles, and database setup
- [RBAC](docs/rbac.md) -- Permission model, system roles, custom roles, evaluation order
- [OIDC and SAML](docs/oidc-saml.md) -- Federated login flows, provider configuration, claim mapping
- [SCIM 2.0](docs/scim.md) -- Directory provisioning, user and group lifecycle
- [Audit and Compliance](docs/audit.md) -- Event logging, querying, export, retention
- [Enterprise Integration](docs/enterprise-integration.md) -- Step-by-step guide for Okta, Entra ID, and Auth0

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=. --cov-fail-under=80
ruff check . && ruff format --check .
pip-audit -r requirements.txt
```

## License

Proprietary -- OCI AI Accelerator Program.
