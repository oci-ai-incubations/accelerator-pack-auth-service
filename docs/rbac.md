# Role-Based Access Control (RBAC)

This guide covers the fine-grained permission model, system and custom roles, permission evaluation, and the backward-compatible legacy role mapping.

## Permission Model Overview

The authorization system uses four layers, evaluated in order:

1. **Role-based permissions** -- Users are assigned roles, and roles have sets of permissions. A user inherits all permissions from all their assigned roles.
2. **Legacy role mapping** -- The user's `role` enum field (admin, user, reader, pending) maps to a system role with predefined permissions, providing backward compatibility.
3. **Direct grants** -- Individual permissions can be granted directly to a user, optionally scoped to a specific resource type and resource ID.
4. **Resource ownership** -- If a user owns a resource (via the `resource_ownership` table), they have implicit access to it.

Additionally, admins (users with `role=admin`) bypass all permission checks entirely.

## System Roles

Four system roles are seeded on startup. System roles cannot be modified or deleted.

| Role | Description | Default Permissions |
|---------|----------------------------------------------|---------------------|
| `admin` | Full access to all resources | All permissions (wildcard) |
| `user` | Standard user with read/write collection access | `collections:read`, `collections:write` |
| `reader` | Read-only access to assigned collections | `collections:read` |
| `pending`| Awaiting admin approval -- no access | (none) |

## System Permissions

The following permissions are seeded on startup:

| Codename | Description | Resource Type |
|---------------------|----------------------------------|---------------|
| `users:list` | List all users | users |
| `users:read` | Read user details | users |
| `users:update` | Update user details | users |
| `users:delete` | Deactivate a user | users |
| `collections:read` | Read collections | collections |
| `collections:write` | Upload to collections | collections |
| `collections:manage` | Manage collection permissions | collections |
| `collections:delete` | Delete collections | collections |
| `roles:list` | List roles | roles |
| `roles:create` | Create roles | roles |
| `roles:read` | Read role details | roles |
| `roles:update` | Update roles | roles |
| `roles:delete` | Delete roles | roles |
| `permissions:list` | List all permissions | permissions |
| `permissions:check` | Check permission for a user | permissions |

## Custom Roles

Custom roles let you define application-specific access profiles beyond the four system roles.

### Create a Custom Role

```bash
curl -X POST http://localhost:8080/auth/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "data-scientist",
    "description": "Read/write access to collections, can list roles"
  }'
```

Response:

```json
{
  "id": 5,
  "name": "data-scientist",
  "description": "Read/write access to collections, can list roles",
  "is_system": false,
  "is_default": false,
  "tenant_id": null,
  "permissions": [],
  "created_at": "2026-03-26T10:00:00"
}
```

### Assign Permissions to a Custom Role

```bash
curl -X PUT http://localhost:8080/auth/roles/5/permissions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permission_codenames": [
      "collections:read",
      "collections:write",
      "roles:list"
    ]
  }'
```

This replaces all existing permissions on the role with the specified set.

### Update a Custom Role

```bash
curl -X PATCH http://localhost:8080/auth/roles/5 \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "is_default": true
  }'
```

Note: System roles cannot be updated. Attempting to modify a system role returns `403 Forbidden`.

### Delete a Custom Role

```bash
curl -X DELETE http://localhost:8080/auth/roles/5 \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Note: System roles cannot be deleted. Attempting to delete a system role returns `403 Forbidden`.

### List All Roles

```bash
curl http://localhost:8080/auth/roles \
  -H "Authorization: Bearer $TOKEN"
```

Requires the `roles:list` permission.

### Get a Single Role

```bash
curl http://localhost:8080/auth/roles/5 \
  -H "Authorization: Bearer $TOKEN"
```

Requires the `roles:read` permission.

## The require_permission() Dependency

Endpoints use the `require_permission()` FastAPI dependency to enforce access. It takes a permission codename and returns a dependency that:

1. Extracts the current user from the JWT.
2. Calls `check_permission()` from the permission service.
3. Returns `403 Forbidden` with the message `"Missing required permission: <codename>"` if the user lacks the permission.

Example usage in a route:

```python
@app.get("/auth/roles", response_model=list[RoleResponse])
async def list_roles(
    _user: User = Depends(require_permission("roles:list")),
    db: AsyncSession = Depends(get_db),
):
    ...
```

## Permission Evaluation Order

When `check_permission()` is called, it evaluates the following checks in order. The first check that grants access short-circuits the remaining checks.

1. **Admin bypass** -- If the user's `role` field is `admin`, access is granted immediately. No further checks are performed.

2. **Role-based permissions** -- The system queries the user's role assignments (via the `user_roles` table), then checks whether any of those roles have the requested permission (via `role_permissions` and `permissions` tables).

3. **Legacy role mapping** -- The user's `role` enum value (e.g., `user`) is matched to the corresponding system role in the `roles` table, and that role's permissions are checked. This provides backward compatibility for users who have not been explicitly assigned roles via the new RBAC model.

4. **Direct grants** -- The system checks the `direct_grants` table for a grant matching the user, permission codename, and (optionally) resource type and resource ID.

5. **Resource ownership** -- If `resource_type` and `resource_id` are provided, the system checks the `resource_ownership` table for a record matching the user and resource. Owners have implicit access to their resources.

If none of these checks grant access, the permission is denied.

## User Role Assignments

### List a User's Roles

```bash
curl http://localhost:8080/auth/users/3/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:

```json
[
  {
    "id": 1,
    "user_id": 3,
    "role_id": 5,
    "role_name": "data-scientist",
    "tenant_id": null,
    "scope_type": null,
    "scope_id": null,
    "created_at": "2026-03-26T10:05:00"
  }
]
```

### Assign a Role to a User

```bash
curl -X POST http://localhost:8080/auth/users/3/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": 5,
    "tenant_id": null,
    "scope_type": "project",
    "scope_id": "project-alpha"
  }'
```

The optional `scope_type` and `scope_id` fields allow scoping a role assignment to a specific resource context (e.g., a project, tenant, or team).

### Remove a Role from a User

```bash
curl -X DELETE http://localhost:8080/auth/users/3/roles/1 \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The path parameter `1` is the assignment ID (not the role ID), as returned by the list or assign endpoints.

## Legacy Collection Permissions

For backward compatibility, the service retains the original collection permission system. This operates independently of the RBAC model and is managed via dedicated endpoints.

| Operation | Endpoint | Auth |
|-----------|----------|------|
| Assign | `POST /auth/collections/{cid}/permissions` | Admin |
| Revoke | `DELETE /auth/collections/{cid}/permissions/{uid}` | Admin |
| List | `GET /auth/collections/{cid}/permissions` | Admin |
| My access | `GET /auth/collections/my-access` | Authenticated |

Collection permissions use three levels: `read`, `write`, and `manage`.

```bash
# Assign write access to user 3 on collection "finance-reports"
curl -X POST http://localhost:8080/auth/collections/finance-reports/permissions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 3, "permission_level": "write"}'
```

```bash
# Check my own collection access
curl http://localhost:8080/auth/collections/my-access \
  -H "Authorization: Bearer $TOKEN"
```

Admin users are not listed in collection permissions because they have implicit full access.

## Permission Check API

The permission check endpoint lets administrators programmatically verify whether a user has a specific permission, useful for debugging access issues.

```bash
curl -X POST http://localhost:8080/auth/permissions/check \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 3,
    "permission": "collections:write",
    "resource_type": "collections",
    "resource_id": "finance-reports"
  }'
```

Response:

```json
{
  "allowed": true,
  "permission": "collections:write",
  "user_id": 3
}
```

Requires the `permissions:check` permission.
