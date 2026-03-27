# SCIM 2.0 Provisioning

This guide covers the SCIM 2.0 (System for Cross-domain Identity Management) implementation, which provides automated user and group lifecycle management per RFC 7644.

## Overview

SCIM 2.0 allows external identity providers and directory services (Okta, Entra ID, OneLogin, etc.) to automatically create, update, deactivate, and delete users and groups in the auth service. This eliminates manual user onboarding and ensures that access is revoked when users are removed from the corporate directory.

The implementation supports:

- User provisioning (create, read, update, replace, deactivate)
- Group provisioning (create, read, update, replace, delete)
- Discovery endpoints (ServiceProviderConfig, Schemas, ResourceTypes)
- Bearer token authentication
- ListResponse format for collection endpoints

## Enabling SCIM

SCIM is disabled by default. To enable it:

1. Set `AUTH_SCIM_ENABLED=true`.
2. Generate a secure bearer token and compute its SHA-256 hash.
3. Set `AUTH_SCIM_TOKEN` to the SHA-256 hash.

```bash
# Generate a token and its hash
SCIM_TOKEN=$(openssl rand -hex 32)
SCIM_TOKEN_HASH=$(echo -n "$SCIM_TOKEN" | sha256sum | awk '{print $1}')

# Set environment variables
export AUTH_SCIM_ENABLED=true
export AUTH_SCIM_TOKEN="$SCIM_TOKEN_HASH"

# Use $SCIM_TOKEN as the bearer token when configuring your IdP
echo "Configure your IdP with this bearer token: $SCIM_TOKEN"
```

Alternatively, use the `enterprise` profile which enables SCIM along with OIDC, SAML, and audit:

```bash
export AUTH_PROFILE=enterprise
export AUTH_SCIM_TOKEN="<sha256-hash-of-your-token>"
```

## Authentication

All SCIM endpoints require a bearer token in the `Authorization` header. The token is validated by computing its SHA-256 hash and comparing it against the configured `AUTH_SCIM_TOKEN` value.

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/ServiceProviderConfig
```

If SCIM is not enabled, all endpoints return `403 Forbidden`. If the token is missing or invalid, endpoints return `401 Unauthorized`.

## Discovery Endpoints

### ServiceProviderConfig

Returns the capabilities of the SCIM implementation.

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/ServiceProviderConfig
```

Response:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "documentationUri": "https://tools.ietf.org/html/rfc7644",
  "patch": {"supported": false},
  "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
  "filter": {"supported": true, "maxResults": 200},
  "changePassword": {"supported": false},
  "sort": {"supported": false},
  "etag": {"supported": false},
  "authenticationSchemes": [
    {
      "type": "oauthbearertoken",
      "name": "OAuth Bearer Token",
      "description": "Authentication via bearer token"
    }
  ]
}
```

### Schemas

Returns the SCIM schemas supported by the service.

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Schemas
```

Response:

```json
[
  {
    "id": "urn:ietf:params:scim:schemas:core:2.0:User",
    "name": "User",
    "description": "User Account"
  },
  {
    "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
    "name": "Group",
    "description": "Group"
  }
]
```

### ResourceTypes

Returns the resource types available via SCIM.

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/ResourceTypes
```

## User Provisioning

### Create a User

```bash
curl -X POST http://localhost:8080/scim/v2/Users \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "jane.doe@example.com",
    "name": {"formatted": "Jane Doe"},
    "displayName": "Jane Doe",
    "emails": [{"value": "jane.doe@example.com", "primary": true}],
    "active": true
  }'
```

Response (201 Created):

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "5",
  "userName": "jane.doe@example.com",
  "name": {"formatted": "Jane Doe"},
  "emails": [{"value": "jane.doe@example.com", "primary": true}],
  "displayName": "Jane Doe",
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2026-03-26T10:30:00"
  }
}
```

Notes:
- The `userName` field is used as the user's email address.
- The `displayName` or `name.formatted` field is used as the user's display name.
- SCIM-provisioned users have `password_hash="!scim-provisioned"` and cannot log in with a password.
- New users are assigned the `user` role by default.
- Returns `409 Conflict` if a user with the same email already exists.

### List Users

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Users
```

Response:

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
      "displayName": "Admin User",
      "active": true,
      "meta": {"resourceType": "User", "created": "2026-03-20T08:00:00"}
    }
  ]
}
```

### Get a User

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Users/5
```

### Update (Replace) a User

```bash
curl -X PUT http://localhost:8080/scim/v2/Users/5 \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "displayName": "Jane M. Doe",
    "active": true
  }'
```

Updatable fields:
- `displayName` or `name.formatted` -- updates the user's name
- `active` -- enables or disables the user account

### Delete (Deactivate) a User

```bash
curl -X DELETE -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Users/5
```

SCIM delete does **not** permanently remove the user record. Instead it:

1. Sets `is_active = false` on the user account.
2. Revokes all active refresh tokens for the user.

This ensures that the user's audit trail and data references remain intact while immediately preventing further access.

## Group Provisioning

### Create a Group

```bash
curl -X POST http://localhost:8080/scim/v2/Groups \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering",
    "externalId": "eng-group-001",
    "members": [
      {"value": "5"},
      {"value": "6"}
    ]
  }'
```

Response (201 Created):

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "1",
  "displayName": "Engineering",
  "externalId": "eng-group-001",
  "meta": {
    "resourceType": "Group",
    "created": "2026-03-26T10:35:00"
  }
}
```

Notes:
- Groups created via SCIM have `source=scim` to distinguish them from locally-created groups.
- Members are specified by user ID (`value` field).

### List Groups

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Groups
```

### Get a Group

```bash
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Groups/1
```

### Update (Replace) a Group

```bash
curl -X PUT http://localhost:8080/scim/v2/Groups/1 \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Platform Engineering",
    "externalId": "eng-group-001"
  }'
```

Updatable fields:
- `displayName` -- updates both `name` and `display_name`
- `externalId` -- updates the external identifier

### Delete a Group

```bash
curl -X DELETE -H "Authorization: Bearer $SCIM_TOKEN" \
  http://localhost:8080/scim/v2/Groups/1
```

Unlike user deletion, group deletion permanently removes the group record and all associated memberships (via cascade).

## User Lifecycle Summary

| IdP Action | SCIM Operation | Auth Service Result |
|------------|---------------|---------------------|
| New hire | POST /scim/v2/Users | User created with `role=user`, `is_active=true` |
| Name change | PUT /scim/v2/Users/{id} | `name` updated |
| Suspend user | PUT /scim/v2/Users/{id} `active: false` | `is_active=false` |
| Reactivate | PUT /scim/v2/Users/{id} `active: true` | `is_active=true` |
| Terminate | DELETE /scim/v2/Users/{id} | `is_active=false`, all tokens revoked |
| Add to group | POST /scim/v2/Groups (with members) | Group created, memberships added |
| Remove from group | PUT /scim/v2/Groups/{id} (without member) | Membership removed on next replace |
