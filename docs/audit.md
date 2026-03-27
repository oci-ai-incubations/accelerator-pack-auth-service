# Audit and Compliance

This guide covers structured audit event logging, querying, export, retention policies, and compliance considerations.

## Overview

When audit logging is enabled (`AUTH_AUDIT_ENABLED=true`), the auth service records structured events for security-relevant actions including logins, user management changes, role assignments, provider configuration changes, and administrative operations. Events are stored in the `audit_logs` database table and are queryable via the REST API.

## Structured Audit Events

Each audit log entry contains the following fields:

| Field | Type | Description |
|-----------------|---------|-------------|
| `id` | integer | Auto-incrementing primary key |
| `timestamp` | datetime | UTC timestamp of the event |
| `event_type` | string | Category of the event (e.g., `login`, `update_user`, `create_role`) |
| `actor_user_id` | integer | ID of the user who performed the action (null for system events) |
| `actor_email` | string | Email of the acting user |
| `target_type` | string | Type of the affected resource (e.g., `user`, `role`, `provider`) |
| `target_id` | string | ID of the affected resource |
| `tenant_id` | integer | Tenant context (for multi-tenant deployments) |
| `details` | JSON | Additional structured data about the event |
| `ip_address` | string | Client IP address |
| `user_agent` | string | Client user agent string |
| `result` | enum | `success` or `failure` |

### Event Types

The following event types are recorded:

| Event Type | Trigger |
|-----------------------|---------|
| `update_user` | Admin updates a user's role, status, or name |
| `assign_permission` | Admin assigns a collection permission |
| `revoke_permission` | Admin revokes a collection permission |
| `create_role` | A new custom role is created |
| `update_role` | A custom role is modified |
| `delete_role` | A custom role is deleted |
| `set_role_permissions` | Permissions on a role are replaced |
| `assign_role` | A role is assigned to a user |
| `remove_role` | A role assignment is removed from a user |
| `create_provider` | An identity provider is created |
| `update_provider` | An identity provider is modified |
| `delete_provider` | An identity provider is deleted |
| `create_claim_mapping`| A claim-to-role mapping is created |
| `delete_claim_mapping`| A claim-to-role mapping is deleted |
| `create_group` | A group is created |
| `add_group_member` | A user is added to a group |
| `set_group_roles` | Group role assignments are updated |
| `purge_audit` | Audit logs are purged |

## Query API

### GET /auth/audit

Query audit logs with filters and pagination. Requires admin access.

**Query Parameters:**

| Parameter | Type | Description |
|----------------|---------|-------------|
| `event_type` | string | Filter by event type |
| `actor_user_id`| integer | Filter by acting user ID |
| `target_type` | string | Filter by target resource type |
| `target_id` | string | Filter by target resource ID |
| `result` | string | Filter by result (`success` or `failure`) |
| `from_date` | datetime| Filter events after this timestamp |
| `to_date` | datetime| Filter events before this timestamp |
| `offset` | integer | Pagination offset (default: 0) |
| `limit` | integer | Page size (default: 50) |

**Example:**

```bash
# Get the last 20 user update events
curl "http://localhost:8080/auth/audit?event_type=update_user&limit=20" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Response:**

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
  "limit": 20
}
```

```bash
# Get all events for a specific user
curl "http://localhost:8080/auth/audit?actor_user_id=3" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

```bash
# Get failure events only
curl "http://localhost:8080/auth/audit?result=failure" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Export

### GET /auth/audit/export

Export all audit logs as a JSON array. Requires admin access. Returns up to 10,000 records.

```bash
curl http://localhost:8080/auth/audit/export \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o audit-export.json
```

The export returns the same field structure as the query API but without pagination metadata. For production use with large datasets, consider streaming via NDJSON (newline-delimited JSON).

## Retention Policy

Audit log retention is controlled by `AUTH_AUDIT_RETENTION_DAYS` (default: 90 days). The purge operation deletes all audit log entries with a `timestamp` older than the retention period.

### POST /auth/audit/purge

Trigger a manual purge. Requires admin access.

```bash
curl -X POST http://localhost:8080/auth/audit/purge \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:

```json
{
  "deleted": 1247
}
```

The purge operation itself is recorded in the audit log with event type `purge_audit`.

### Recommended Practices

- **Schedule regular purges** using a cron job or Kubernetes CronJob that calls the purge endpoint.
- **Export before purging** if you need to retain logs beyond the retention period for compliance.
- **Set retention based on compliance requirements**: SOC 2 typically requires 1 year (set `AUTH_AUDIT_RETENTION_DAYS=365`), GDPR may require shorter retention for personal data.

## Compliance Considerations

### SOC 2

The audit log satisfies SOC 2 Common Criteria related to:
- **CC6.1** -- Logical access security events are logged with actor, action, target, and timestamp.
- **CC7.2** -- Security events are monitored (via the query API) and can be exported for SIEM ingestion.
- **CC7.3** -- Audit logs are retained for a configurable period.

### GDPR

- Audit logs may contain personal data (email addresses, user IDs). Ensure your retention policy aligns with data minimization principles.
- The purge endpoint supports the right to erasure by removing old logs.
- Export functionality supports data portability requirements.

### HIPAA

- For HIPAA deployments, set `AUTH_AUDIT_RETENTION_DAYS=2190` (6 years) per the HIPAA retention requirement.
- Ensure the database backing the audit logs has encryption at rest enabled.

### General Recommendations

1. **Do not disable audit logging in production.** Use `AUTH_AUDIT_ENABLED=true` (or the `standard`/`enterprise` profiles).
2. **Export logs regularly** to a centralized SIEM or log management system.
3. **Restrict admin access** -- only admin users can query, export, and purge audit logs.
4. **Monitor for anomalies** -- watch for unusual patterns such as repeated `failure` results, bulk permission changes, or provider configuration changes outside of maintenance windows.
