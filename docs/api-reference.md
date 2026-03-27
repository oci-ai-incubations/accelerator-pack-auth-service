# API Reference

Complete endpoint reference for the Enterprise Auth Service. All endpoints are prefixed with `/auth/` unless otherwise noted. The service listens on port 8080 by default.

## Authentication

Most endpoints require a JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Auth levels used in this document:

- **None** -- No authentication required
- **Authenticated** -- Any valid JWT
- **Admin** -- JWT with `role=admin`
- **Permission** -- Specific permission codename required (checked via RBAC)
- **SCIM** -- SCIM bearer token (separate from JWT)

---

## Health

### GET /auth/health

Readiness check. Returns service status and version.

**Auth:** None

**Response (200):**

```json
{
  "status": "healthy",
  "service": "auth",
  "version": "1.0.0"
}
```

### GET /auth/alive

Liveness check.

**Auth:** None

**Response (200):**

```json
{
  "status": "alive"
}
```

---

## Authentication

### POST /auth/register

Register a new user. The first user is auto-promoted to admin. Disabled when `AUTH_LOCAL_AUTH_ENABLED=false`.

**Auth:** None
**Rate Limit:** `AUTH_RATE_LIMIT_REGISTER` (default: 5/minute)

**Request:**

```json
{
  "email": "user@example.com",
  "password": "minimum8chars",
  "name": "User Name"
}
```

| Field | Type | Constraints |
|-------|------|-------------|
| `email` | string | Valid email address |
| `password` | string | 8-128 characters |
| `name` | string | 1-255 characters |

**Response (201):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "dGhpcyBpcyBhIHNlY3VyZSB0b2tlbg...",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "name": "User Name",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-03-26T10:00:00"
  }
}
```

**Errors:**

| Status | Detail |
|--------|--------|
| 403 | Local authentication is disabled. Use SSO. |
| 409 | Email already registered |

### POST /auth/login

Authenticate with email and password. Disabled when `AUTH_LOCAL_AUTH_ENABLED=false`.

**Auth:** None
**Rate Limit:** `AUTH_RATE_LIMIT_LOGIN` (default: 10/minute)

**Request:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response (200):** Same structure as register.

**Errors:**

| Status | Detail |
|--------|--------|
| 401 | Invalid email or password |
| 403 | Local authentication is disabled. Use SSO. |
| 403 | Account is deactivated |
| 429 | Account temporarily locked due to too many failed login attempts |

### POST /auth/refresh

Exchange a refresh token for a new token pair. The used refresh token is revoked (rotation).

**Auth:** None

**Request:**

```json
{
  "refresh_token": "dGhpcyBpcyBhIHNlY3VyZSB0b2tlbg..."
}
```

**Response (200):** Same structure as register.

**Errors:**

| Status | Detail |
|--------|--------|
| 401 | Invalid or expired refresh token |
| 401 | User not found or inactive |

### POST /auth/logout

Blacklist the current access token and revoke all refresh tokens.

**Auth:** Authenticated

**Response:** 204 No Content

### POST /auth/token/revoke

Blacklist a specific access token by its JTI.

**Auth:** Authenticated

**Request:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 400 | Token has no JTI |

---

## Current User

### GET /auth/me

Get the authenticated user's profile.

**Auth:** Authenticated

**Response (200):**

```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "User Name",
  "role": "admin",
  "is_active": true,
  "created_at": "2026-03-26T10:00:00"
}
```

---

## User Management

### GET /auth/users

List all users, ordered by creation date (newest first).

**Auth:** Admin

**Response (200):**

```json
[
  {
    "id": 1,
    "email": "admin@example.com",
    "name": "Admin User",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-03-26T10:00:00"
  }
]
```

### PATCH /auth/users/{user_id}

Update a user's role, active status, or name.

**Auth:** Admin

**Request:**

```json
{
  "role": "user",
  "is_active": true,
  "name": "Updated Name"
}
```

All fields are optional. Only provided fields are updated.

| Field | Type | Values |
|-------|------|--------|
| `role` | string | `admin`, `user`, `reader`, `pending` |
| `is_active` | boolean | `true`, `false` |
| `name` | string | New display name |

**Response (200):** UserResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | User not found |

---

## User Role Assignments

### GET /auth/users/{user_id}/roles

List role assignments for a user.

**Auth:** Admin

**Response (200):**

```json
[
  {
    "id": 1,
    "user_id": 3,
    "role_id": 5,
    "role_name": "data-scientist",
    "tenant_id": null,
    "scope_type": "project",
    "scope_id": "alpha",
    "created_at": "2026-03-26T10:05:00"
  }
]
```

### POST /auth/users/{user_id}/roles

Assign a role to a user.

**Auth:** Admin

**Request:**

```json
{
  "role_id": 5,
  "tenant_id": null,
  "scope_type": "project",
  "scope_id": "alpha"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role_id` | integer | Yes | ID of the role to assign |
| `tenant_id` | integer | No | Tenant scope |
| `scope_type` | string | No | Scope category (e.g., `project`, `team`) |
| `scope_id` | string | No | Scope identifier |

**Response (201):** UserRoleResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | User not found |
| 404 | Role not found |

### DELETE /auth/users/{user_id}/roles/{assignment_id}

Remove a role assignment. The `assignment_id` is the ID of the assignment record, not the role ID.

**Auth:** Admin

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Role assignment not found |

---

## Collection Permissions (Legacy)

### POST /auth/collections/{collection_id}/permissions

Assign a permission to a user on a collection.

**Auth:** Admin

**Request:**

```json
{
  "user_id": 3,
  "permission_level": "write"
}
```

| Field | Type | Values |
|-------|------|--------|
| `user_id` | integer | Target user ID |
| `permission_level` | string | `read`, `write`, `manage` |

**Response (201):**

```json
{
  "id": 1,
  "user_id": 3,
  "collection_id": "finance-reports",
  "permission_level": "write",
  "user_email": "jane@example.com"
}
```

### DELETE /auth/collections/{collection_id}/permissions/{user_id}

Revoke a user's permission on a collection.

**Auth:** Admin

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Permission not found |

### GET /auth/collections/{collection_id}/permissions

List all permissions for a collection.

**Auth:** Admin

**Response (200):**

```json
[
  {
    "id": 1,
    "user_id": 3,
    "collection_id": "finance-reports",
    "permission_level": "write",
    "user_email": "jane@example.com"
  }
]
```

### GET /auth/collections/my-access

List the authenticated user's collection access. Returns an empty list for admin users (they have implicit full access).

**Auth:** Authenticated

**Response (200):**

```json
[
  {
    "collection_id": "finance-reports",
    "permission_level": "write"
  }
]
```

---

## Roles

### GET /auth/roles

List all roles with their assigned permissions.

**Auth:** Permission `roles:list`

**Response (200):**

```json
[
  {
    "id": 1,
    "name": "admin",
    "description": "Full access to all resources",
    "is_system": true,
    "is_default": false,
    "tenant_id": null,
    "permissions": ["users:list", "users:read", "users:update", "..."],
    "created_at": "2026-03-26T10:00:00"
  }
]
```

### POST /auth/roles

Create a custom role.

**Auth:** Permission `roles:create`

**Request:**

```json
{
  "name": "data-scientist",
  "description": "Read/write access to collections",
  "tenant_id": null
}
```

| Field | Type | Constraints |
|-------|------|-------------|
| `name` | string | 1-100 characters |
| `description` | string | Optional |
| `tenant_id` | integer | Optional tenant scope |

**Response (201):** RoleResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 409 | Role name already exists |

### GET /auth/roles/{role_id}

Get a single role with its permissions.

**Auth:** Permission `roles:read`

**Response (200):** RoleResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Role not found |

### PATCH /auth/roles/{role_id}

Update a custom role. System roles cannot be modified.

**Auth:** Permission `roles:update`

**Request:**

```json
{
  "name": "senior-data-scientist",
  "description": "Updated description",
  "is_default": false
}
```

All fields are optional.

**Response (200):** RoleResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 403 | Cannot modify system roles |
| 404 | Role not found |

### DELETE /auth/roles/{role_id}

Delete a custom role. System roles cannot be deleted.

**Auth:** Permission `roles:delete`

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 403 | Cannot delete system roles |
| 404 | Role not found |

### PUT /auth/roles/{role_id}/permissions

Replace all permissions on a role. System roles cannot be modified.

**Auth:** Permission `roles:update`

**Request:**

```json
{
  "permission_codenames": [
    "collections:read",
    "collections:write",
    "roles:list"
  ]
}
```

**Response (200):** RoleResponse object with updated permissions.

**Errors:**

| Status | Detail |
|--------|--------|
| 403 | Cannot modify system role permissions |
| 404 | Role not found |

---

## Permissions

### GET /auth/permissions

List all available permissions.

**Auth:** Permission `permissions:list`

**Response (200):**

```json
[
  {
    "id": 1,
    "codename": "collections:read",
    "description": "Read collections",
    "resource_type": "collections"
  }
]
```

### POST /auth/permissions/check

Check whether a user has a specific permission.

**Auth:** Permission `permissions:check`

**Request:**

```json
{
  "user_id": 3,
  "permission": "collections:write",
  "resource_type": "collections",
  "resource_id": "finance-reports"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | integer | Yes | User to check |
| `permission` | string | Yes | Permission codename |
| `resource_type` | string | No | Resource type for scoped checks |
| `resource_id` | string | No | Resource ID for scoped checks |

**Response (200):**

```json
{
  "allowed": true,
  "permission": "collections:write",
  "user_id": 3
}
```

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | User not found |

---

## Identity Providers

### GET /auth/providers

List all identity providers.

**Auth:** Admin

**Response (200):**

```json
[
  {
    "id": 1,
    "type": "oidc",
    "name": "Okta Production",
    "slug": "okta-prod",
    "config": {"client_id": "...", "...": "..."},
    "tenant_id": null,
    "is_active": true,
    "priority": 10,
    "created_at": "2026-03-26T10:00:00"
  }
]
```

### POST /auth/providers

Create an identity provider.

**Auth:** Admin

**Request:**

```json
{
  "type": "oidc",
  "name": "Okta Production",
  "slug": "okta-prod",
  "config": {
    "client_id": "0oaXXX",
    "client_secret": "secret",
    "authorize_url": "https://company.okta.com/oauth2/default/v1/authorize",
    "token_url": "https://company.okta.com/oauth2/default/v1/token"
  },
  "tenant_id": null,
  "is_active": true,
  "priority": 10
}
```

| Field | Type | Constraints |
|-------|------|-------------|
| `type` | string | `oidc` or `saml` |
| `name` | string | 1-255 characters |
| `slug` | string | 1-100 characters, lowercase alphanumeric with hyphens |
| `config` | object | Provider-specific configuration |
| `tenant_id` | integer | Optional tenant scope |
| `is_active` | boolean | Default: true |
| `priority` | integer | Default: 0. Higher values = higher priority |

**Response (201):** ProviderResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 409 | Slug already exists |

### GET /auth/providers/{provider_id}

Get a single provider.

**Auth:** Admin

**Response (200):** ProviderResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Provider not found |

### PATCH /auth/providers/{provider_id}

Update a provider.

**Auth:** Admin

**Request:**

```json
{
  "name": "Updated Name",
  "config": {"client_id": "new-id"},
  "is_active": false,
  "priority": 5
}
```

All fields are optional.

**Response (200):** ProviderResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Provider not found |

### DELETE /auth/providers/{provider_id}

Delete a provider and all its claim mappings.

**Auth:** Admin

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Provider not found |

---

## Claim Mappings

### GET /auth/providers/{provider_id}/mappings

List claim-to-role mappings for a provider, ordered by priority (highest first).

**Auth:** Admin

**Response (200):**

```json
[
  {
    "id": 1,
    "provider_id": 1,
    "claim_key": "groups",
    "claim_value_pattern": "Platform-Admins",
    "role_id": 1,
    "priority": 20,
    "is_regex": false
  }
]
```

### POST /auth/providers/{provider_id}/mappings

Create a claim-to-role mapping.

**Auth:** Admin

**Request:**

```json
{
  "claim_key": "groups",
  "claim_value_pattern": "Engineering",
  "role_id": 2,
  "priority": 10,
  "is_regex": false
}
```

| Field | Type | Constraints |
|-------|------|-------------|
| `claim_key` | string | 1-255 characters. The claim/attribute name from the IdP. |
| `claim_value_pattern` | string | 1-255 characters. Exact value or regex pattern. |
| `role_id` | integer | ID of the role to assign |
| `priority` | integer | Default: 0. Higher values = evaluated first. |
| `is_regex` | boolean | Default: false. Whether to use regex matching. |

**Response (201):** ClaimMappingResponse object.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Provider not found |
| 404 | Role not found |

### DELETE /auth/providers/{provider_id}/mappings/{mapping_id}

Delete a claim mapping.

**Auth:** Admin

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Mapping not found |

---

## SSO Callback

### POST /auth/sso/callback

Generic SSO callback endpoint. Called after the frontend completes the OIDC authorization code exchange or SAML assertion validation. Performs JIT provisioning and issues internal tokens.

**Auth:** None

**Request:**

```json
{
  "provider_slug": "okta-prod",
  "external_id": "00uXXXXXXXXXXXXXXX",
  "email": "user@example.com",
  "name": "User Name",
  "claims": {
    "groups": ["Engineering", "Data-Team"],
    "department": "Technology"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider_slug` | string | Yes | Slug of the identity provider |
| `external_id` | string | Yes | User's unique ID in the external provider |
| `email` | string | Yes | User's email address |
| `name` | string | No | User's display name (default: "SSO User") |
| `claims` | object | No | Raw claims/attributes from the IdP |

**Response (200):** TokenResponse (same structure as login).

**Errors:**

| Status | Detail |
|--------|--------|
| 400 | provider_slug required |
| 404 | Provider not found |

---

## Groups

### GET /auth/groups

List all groups.

**Auth:** Admin

**Response (200):**

```json
[
  {
    "id": 1,
    "name": "Engineering",
    "display_name": "Engineering",
    "source": "local",
    "external_id": null
  }
]
```

### POST /auth/groups

Create a group.

**Auth:** Admin

**Request:**

```json
{
  "name": "Engineering",
  "display_name": "Engineering Team",
  "description": "All engineering staff"
}
```

**Response (201):**

```json
{
  "id": 1,
  "name": "Engineering",
  "display_name": "Engineering Team"
}
```

### GET /auth/groups/{group_id}/members

List members of a group.

**Auth:** Admin

**Response (200):** Array of UserResponse objects.

### POST /auth/groups/{group_id}/members

Add a user to a group.

**Auth:** Admin

**Request:**

```json
{
  "user_id": 3
}
```

**Response (201):**

```json
{
  "group_id": 1,
  "user_id": 3
}
```

### DELETE /auth/groups/{group_id}/members/{user_id}

Remove a user from a group.

**Auth:** Admin

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Membership not found |

### PUT /auth/groups/{group_id}/roles

Replace all role assignments for a group.

**Auth:** Admin

**Request:**

```json
{
  "role_ids": [2, 5]
}
```

**Response (200):**

```json
{
  "group_id": 1,
  "role_ids": [2, 5]
}
```

---

## SCIM 2.0

All SCIM endpoints are prefixed with `/scim/v2/` and require SCIM bearer token authentication. SCIM must be enabled (`AUTH_SCIM_ENABLED=true`) and a token configured (`AUTH_SCIM_TOKEN`).

### GET /scim/v2/ServiceProviderConfig

SCIM service provider configuration and capabilities.

**Auth:** SCIM

**Response (200):** ServiceProviderConfig resource per RFC 7643.

### GET /scim/v2/Schemas

SCIM schema definitions.

**Auth:** SCIM

**Response (200):** Array of Schema resources.

### GET /scim/v2/ResourceTypes

SCIM resource type definitions.

**Auth:** SCIM

**Response (200):** Array of ResourceType resources.

### GET /scim/v2/Users

List all users in SCIM format.

**Auth:** SCIM

**Response (200):**

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 3,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "1",
      "userName": "admin@example.com",
      "name": {"formatted": "Admin User"},
      "emails": [{"value": "admin@example.com", "primary": true}],
      "displayName": "Admin User",
      "active": true,
      "meta": {"resourceType": "User", "created": "2026-03-26T10:00:00"}
    }
  ]
}
```

### POST /scim/v2/Users

Create a user via SCIM.

**Auth:** SCIM

**Request:**

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "jane@example.com",
  "displayName": "Jane Doe",
  "active": true
}
```

**Response (201):** SCIM User resource.

**Errors:**

| Status | Detail |
|--------|--------|
| 409 | User already exists |

### GET /scim/v2/Users/{user_id}

Get a user by ID in SCIM format.

**Auth:** SCIM

**Response (200):** SCIM User resource.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | User not found |

### PUT /scim/v2/Users/{user_id}

Replace a user's attributes.

**Auth:** SCIM

**Request:** SCIM User resource with updated fields.

**Response (200):** Updated SCIM User resource.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | User not found |

### DELETE /scim/v2/Users/{user_id}

Deactivate a user (sets `active=false` and revokes all tokens).

**Auth:** SCIM

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | User not found |

### GET /scim/v2/Groups

List all groups in SCIM format.

**Auth:** SCIM

**Response (200):**

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 2,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      "id": "1",
      "displayName": "Engineering",
      "externalId": "eng-001",
      "meta": {"resourceType": "Group", "created": "2026-03-26T10:00:00"}
    }
  ]
}
```

### POST /scim/v2/Groups

Create a group via SCIM.

**Auth:** SCIM

**Request:**

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "Engineering",
  "externalId": "eng-001",
  "members": [{"value": "3"}, {"value": "5"}]
}
```

**Response (201):** SCIM Group resource.

### GET /scim/v2/Groups/{group_id}

Get a group by ID in SCIM format.

**Auth:** SCIM

**Response (200):** SCIM Group resource.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Group not found |

### PUT /scim/v2/Groups/{group_id}

Replace a group's attributes.

**Auth:** SCIM

**Request:** SCIM Group resource with updated fields.

**Response (200):** Updated SCIM Group resource.

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Group not found |

### DELETE /scim/v2/Groups/{group_id}

Permanently delete a group and all memberships.

**Auth:** SCIM

**Response:** 204 No Content

**Errors:**

| Status | Detail |
|--------|--------|
| 404 | Group not found |

---

## Audit

### GET /auth/audit

Query audit logs with filters and pagination.

**Auth:** Admin

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Filter by event type |
| `actor_user_id` | integer | Filter by acting user |
| `target_type` | string | Filter by target resource type |
| `target_id` | string | Filter by target resource ID |
| `result` | string | Filter by result (`success` or `failure`) |
| `offset` | integer | Pagination offset (default: 0) |
| `limit` | integer | Page size (default: 50) |

**Response (200):**

```json
{
  "items": [
    {
      "id": 42,
      "timestamp": "2026-03-26T14:30:00",
      "event_type": "update_user",
      "actor_user_id": 1,
      "actor_email": null,
      "target_type": null,
      "target_id": null,
      "tenant_id": null,
      "details": null,
      "ip_address": null,
      "user_agent": null,
      "result": "success"
    }
  ],
  "total": 1,
  "offset": 0,
  "limit": 50
}
```

### GET /auth/audit/export

Export all audit logs as a JSON array (up to 10,000 records).

**Auth:** Admin

**Response (200):** Array of audit log objects.

### POST /auth/audit/purge

Delete audit logs older than the retention period (`AUTH_AUDIT_RETENTION_DAYS`).

**Auth:** Admin

**Response (200):**

```json
{
  "deleted": 1247
}
```

---

## Admin Dashboard

### GET /auth/admin/status

System status overview with feature flags and aggregate statistics.

**Auth:** Admin

**Response (200):**

```json
{
  "version": "1.0.0",
  "profile": "enterprise",
  "features": {
    "local_auth": true,
    "oidc": true,
    "saml": true,
    "scim": true,
    "audit": true
  },
  "stats": {
    "total_users": 150,
    "active_users": 142,
    "active_sessions": 87,
    "identity_providers": 2,
    "groups": 12
  }
}
```
