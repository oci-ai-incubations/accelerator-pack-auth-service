# Configuration Reference

All configuration is via environment variables with the `AUTH_` prefix. The service uses Pydantic Settings for validation and type coercion.

## Profile Presets

Set `AUTH_PROFILE` to apply a preset. Individual environment variables override preset values when explicitly set.

| Profile | `local_auth` | `oidc` | `saml` | `scim` | `audit` |
|------------|-------------|--------|--------|--------|---------|
| `minimal` | true | false | false | false | false |
| `standard` | true | true | false | false | true |
| `enterprise`| true | true | true | true | true |
| `custom` | (manual) | (manual) | (manual) | (manual) | (manual) |

The `custom` profile (default) does not apply any presets. All flags retain their individual defaults.

**How overrides work:** Profile presets are applied during settings initialization. If an environment variable is explicitly set (e.g., `AUTH_OIDC_ENABLED=false`), it takes precedence over the profile preset. This means you can use `AUTH_PROFILE=enterprise` and selectively disable features.

## Complete Environment Variable Reference

### Database

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUTH_DATABASE_URL` | string | `sqlite+aiosqlite:///./auth.db` | SQLAlchemy async database URL |
| `AUTH_DATABASE_TYPE` | string | `auto` | Database type override: `auto`, `sqlite`, `postgres`, `oracle` |
| `AUTH_ORACLE_CONNECTION_STRING` | string | (empty) | Oracle 26ai connection DSN (e.g., `tcps://host:1521/service`) |
| `AUTH_ORACLE_USER` | string | (empty) | Oracle database username |
| `AUTH_ORACLE_PASSWORD` | string | (empty) | Oracle database password |

### JWT

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUTH_JWT_SECRET` | string | `change-me-in-production` | Secret key for JWT signing. **Must be changed in production.** |
| `AUTH_JWT_ALGORITHM` | string | `HS256` | JWT signing algorithm |
| `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` | integer | `15` | Access token lifetime in minutes |
| `AUTH_REFRESH_TOKEN_EXPIRE_DAYS` | integer | `7` | Refresh token lifetime in days |

### Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUTH_BCRYPT_ROUNDS` | integer | `12` | bcrypt hashing cost factor |
| `AUTH_CORS_ORIGINS` | string | `*` | Comma-separated list of allowed CORS origins. Set to specific origins in production. |
| `AUTH_RATE_LIMIT_LOGIN` | string | `10/minute` | Rate limit for the login endpoint (slowapi format) |
| `AUTH_RATE_LIMIT_REGISTER` | string | `5/minute` | Rate limit for the registration endpoint |
| `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` | integer | `5` | Number of failed login attempts before temporary lockout |
| `AUTH_ACCOUNT_LOCKOUT_DURATION_MINUTES` | integer | `30` | Duration of account lockout window in minutes |
| `AUTH_MAX_CONCURRENT_SESSIONS` | integer | `5` | Maximum number of active refresh tokens per user. Oldest tokens are revoked when the limit is exceeded. |

### Feature Flags

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUTH_LOCAL_AUTH_ENABLED` | boolean | `true` | Enable local username/password registration and login |
| `AUTH_OIDC_ENABLED` | boolean | `false` | Enable OIDC authentication (provider management and SSO callback) |
| `AUTH_SAML_ENABLED` | boolean | `false` | Enable SAML authentication |
| `AUTH_SCIM_ENABLED` | boolean | `false` | Enable SCIM 2.0 provisioning endpoints |
| `AUTH_SCIM_TOKEN` | string | (empty) | SHA-256 hash of the SCIM bearer token. Required when SCIM is enabled. |
| `AUTH_AUDIT_ENABLED` | boolean | `true` | Enable audit event logging |
| `AUTH_AUDIT_RETENTION_DAYS` | integer | `90` | Number of days to retain audit logs before purge |

### Behavior

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUTH_PROFILE` | string | `custom` | Configuration profile preset: `minimal`, `standard`, `enterprise`, or `custom` |
| `AUTH_AUTO_ADMIN_FIRST_USER` | boolean | `true` | Automatically promote the first registered user to admin |

## Database Configuration

### SQLite (Development)

The default configuration. No additional setup needed.

```bash
export AUTH_DATABASE_URL="sqlite+aiosqlite:///./auth.db"
```

SQLite is suitable for development and single-instance deployments. It does not support concurrent writes from multiple processes.

### PostgreSQL (Staging / Production)

```bash
export AUTH_DATABASE_URL="postgresql+asyncpg://user:password@hostname:5432/authdb"
```

PostgreSQL provides full ACID compliance, concurrent access, and production-grade performance. The engine is configured with a connection pool of size 5 and max overflow of 10.

### Oracle 26ai (Enterprise Production)

Oracle 26ai support uses the `oracledb` async driver in thin mode.

```bash
export AUTH_DATABASE_TYPE="oracle"
export AUTH_ORACLE_CONNECTION_STRING="tcps://db-host:1521/auth_service"
export AUTH_ORACLE_USER="auth_app"
export AUTH_ORACLE_PASSWORD="secure-password"
```

Alternatively, if `AUTH_DATABASE_TYPE=auto` (the default), the engine auto-detects Oracle when `AUTH_ORACLE_CONNECTION_STRING` is set.

The Oracle engine is configured with pool size 5 and max overflow 10, running in thin mode (no Oracle Client required).

## Auto-Detection Logic

When `AUTH_DATABASE_TYPE=auto` (the default), the database type is determined as follows:

1. If `AUTH_ORACLE_CONNECTION_STRING` is set and non-empty, use Oracle.
2. If `AUTH_DATABASE_URL` contains `postgresql`, use PostgreSQL.
3. Otherwise, use SQLite.

## Security Headers

The service adds the following security headers to all responses:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |

## Example Configurations

### Minimal Development

```bash
export AUTH_PROFILE=minimal
export AUTH_JWT_SECRET=dev-secret
```

### Standard with PostgreSQL

```bash
export AUTH_PROFILE=standard
export AUTH_JWT_SECRET=$(openssl rand -hex 32)
export AUTH_DATABASE_URL="postgresql+asyncpg://auth:password@localhost:5432/auth"
export AUTH_CORS_ORIGINS="https://app.example.com"
```

### Full Enterprise with Oracle 26ai

```bash
export AUTH_PROFILE=enterprise
export AUTH_JWT_SECRET=$(openssl rand -hex 32)
export AUTH_DATABASE_TYPE=oracle
export AUTH_ORACLE_CONNECTION_STRING="tcps://oracle-host:1521/auth_pdb"
export AUTH_ORACLE_USER=auth_svc
export AUTH_ORACLE_PASSWORD=secure-password
export AUTH_CORS_ORIGINS="https://app.example.com,https://admin.example.com"
export AUTH_SCIM_TOKEN=$(echo -n "your-scim-token" | sha256sum | awk '{print $1}')
export AUTH_AUDIT_RETENTION_DAYS=365
export AUTH_ACCOUNT_LOCKOUT_THRESHOLD=3
export AUTH_MAX_CONCURRENT_SESSIONS=3
```
