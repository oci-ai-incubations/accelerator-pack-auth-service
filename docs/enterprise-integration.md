# Enterprise Integration Guide

Step-by-step instructions for integrating the auth service with enterprise identity providers. This guide covers OIDC and SAML setup with Okta, Microsoft Entra ID, and Auth0, SCIM provisioning, role mapping strategy, and troubleshooting.

## Prerequisites

- Auth service deployed and accessible (e.g., `https://auth.example.com`)
- Admin account created (the first registered user is auto-promoted)
- Admin JWT token obtained via login:

```bash
# Register the first user (becomes admin)
curl -X POST https://auth.example.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "SecurePass123!", "name": "Admin User"}'

# Login to get tokens
RESPONSE=$(curl -s -X POST https://auth.example.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "SecurePass123!"}')

ADMIN_TOKEN=$(echo $RESPONSE | jq -r '.access_token')
```

- Enterprise profile enabled:

```bash
export AUTH_PROFILE=enterprise
export AUTH_JWT_SECRET=$(openssl rand -hex 32)
```

## OIDC Setup

### Okta

**Step 1: Create an Okta Application**

1. In the Okta admin console, go to Applications > Create App Integration.
2. Select "OIDC - OpenID Connect" and "Web Application".
3. Set the sign-in redirect URI to your frontend callback URL (e.g., `https://app.example.com/auth/callback`).
4. Set the sign-out redirect URI to `https://app.example.com`.
5. Under Assignments, assign the application to the appropriate users/groups.
6. Note the Client ID, Client Secret, and Okta domain.

**Step 2: Register the Provider**

```bash
curl -X POST https://auth.example.com/auth/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "oidc",
    "name": "Okta",
    "slug": "okta",
    "config": {
      "client_id": "0oaXXXXXXXXXXXXXXXX",
      "client_secret": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      "authorize_url": "https://company.okta.com/oauth2/default/v1/authorize",
      "token_url": "https://company.okta.com/oauth2/default/v1/token",
      "userinfo_url": "https://company.okta.com/oauth2/default/v1/userinfo",
      "jwks_uri": "https://company.okta.com/oauth2/default/v1/keys",
      "scopes": ["openid", "profile", "email", "groups"],
      "redirect_uri": "https://app.example.com/auth/callback"
    },
    "is_active": true,
    "priority": 10
  }'
```

**Step 3: Configure Claim Mappings**

Map Okta groups to internal roles. First, list the available roles to get their IDs:

```bash
curl https://auth.example.com/auth/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Then create mappings:

```bash
# Map "Platform-Admins" group to admin role (role_id=1)
curl -X POST https://auth.example.com/auth/providers/1/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "claim_key": "groups",
    "claim_value_pattern": "Platform-Admins",
    "role_id": 1,
    "priority": 20,
    "is_regex": false
  }'

# Map "Data-Scientists" group to a custom role (role_id=5)
curl -X POST https://auth.example.com/auth/providers/1/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "claim_key": "groups",
    "claim_value_pattern": "Data-Scientists",
    "role_id": 5,
    "priority": 10,
    "is_regex": false
  }'
```

### Microsoft Entra ID (Azure AD)

**Step 1: Register an Application in Entra ID**

1. In the Azure portal, go to Entra ID > App registrations > New registration.
2. Set the redirect URI to `https://app.example.com/auth/callback` (Web platform).
3. Under Certificates & secrets, create a new client secret.
4. Under API permissions, add `openid`, `profile`, `email`. Optionally add `GroupMember.Read.All` for group claims.
5. Under Token configuration, add the `groups` optional claim to the ID token.
6. Note the Application (client) ID, Directory (tenant) ID, and client secret.

**Step 2: Register the Provider**

```bash
curl -X POST https://auth.example.com/auth/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "oidc",
    "name": "Entra ID",
    "slug": "entra-id",
    "config": {
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "your-client-secret",
      "authorize_url": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize",
      "token_url": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token",
      "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
      "jwks_uri": "https://login.microsoftonline.com/TENANT_ID/discovery/v2.0/keys",
      "scopes": ["openid", "profile", "email"],
      "redirect_uri": "https://app.example.com/auth/callback"
    },
    "is_active": true,
    "priority": 10
  }'
```

**Step 3: Configure Claim Mappings**

Entra ID sends group memberships as object IDs by default. Map them accordingly:

```bash
# Map Entra ID group object ID to admin role
curl -X POST https://auth.example.com/auth/providers/2/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "claim_key": "groups",
    "claim_value_pattern": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "role_id": 1,
    "priority": 20,
    "is_regex": false
  }'
```

### Auth0

**Step 1: Create an Auth0 Application**

1. In the Auth0 dashboard, go to Applications > Create Application > Regular Web Application.
2. Set Allowed Callback URLs to `https://app.example.com/auth/callback`.
3. Under Settings, note the Domain, Client ID, and Client Secret.
4. Under Connections, enable the identity sources you want (e.g., database, social, enterprise).

**Step 2: Register the Provider**

```bash
curl -X POST https://auth.example.com/auth/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "oidc",
    "name": "Auth0",
    "slug": "auth0",
    "config": {
      "client_id": "your-client-id",
      "client_secret": "your-client-secret",
      "authorize_url": "https://your-tenant.auth0.com/authorize",
      "token_url": "https://your-tenant.auth0.com/oauth/token",
      "userinfo_url": "https://your-tenant.auth0.com/userinfo",
      "jwks_uri": "https://your-tenant.auth0.com/.well-known/jwks.json",
      "scopes": ["openid", "profile", "email"],
      "redirect_uri": "https://app.example.com/auth/callback"
    },
    "is_active": true,
    "priority": 10
  }'
```

## SAML Setup

### Okta SAML

**Step 1: Create a SAML Integration in Okta**

1. In the Okta admin console, go to Applications > Create App Integration > SAML 2.0.
2. Set the Single sign-on URL (ACS URL) to `https://app.example.com/auth/saml/acs`.
3. Set the Audience URI (SP Entity ID) to `https://app.example.com`.
4. Under Attribute Statements, add mappings for `email`, `name`, and any group attributes.
5. Download the IdP metadata or note the IdP SSO URL and signing certificate.

**Step 2: Register the Provider**

```bash
curl -X POST https://auth.example.com/auth/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "saml",
    "name": "Okta SAML",
    "slug": "okta-saml",
    "config": {
      "idp_entity_id": "http://www.okta.com/exkXXXXXXXXXXXXXXX",
      "idp_sso_url": "https://company.okta.com/app/company_app/exkXXXXXXXX/sso/saml",
      "idp_certificate": "MIIC...(base64-encoded certificate)...",
      "sp_entity_id": "https://app.example.com",
      "acs_url": "https://app.example.com/auth/saml/acs",
      "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    },
    "is_active": true,
    "priority": 5
  }'
```

### Entra ID SAML

**Step 1: Create an Enterprise Application**

1. In the Azure portal, go to Entra ID > Enterprise applications > New application > Create your own application.
2. Select "Integrate any other application you don't find in the gallery (Non-gallery)".
3. Under Single sign-on, select SAML.
4. Set the Identifier (Entity ID) to `https://app.example.com`.
5. Set the Reply URL (ACS URL) to `https://app.example.com/auth/saml/acs`.
6. Download the Federation Metadata XML or note the Login URL and certificate.

**Step 2: Register the Provider**

```bash
curl -X POST https://auth.example.com/auth/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "saml",
    "name": "Entra ID SAML",
    "slug": "entra-saml",
    "config": {
      "idp_entity_id": "https://sts.windows.net/TENANT_ID/",
      "idp_sso_url": "https://login.microsoftonline.com/TENANT_ID/saml2",
      "idp_certificate": "MIIC...(base64-encoded certificate)...",
      "sp_entity_id": "https://app.example.com",
      "acs_url": "https://app.example.com/auth/saml/acs"
    },
    "is_active": true,
    "priority": 5
  }'
```

## SCIM Provisioning Setup

SCIM enables automatic user and group synchronization from your identity provider.

### Step 1: Generate a SCIM Token

```bash
SCIM_TOKEN=$(openssl rand -hex 32)
SCIM_TOKEN_HASH=$(echo -n "$SCIM_TOKEN" | sha256sum | awk '{print $1}')

echo "SCIM Bearer Token (configure in IdP): $SCIM_TOKEN"
echo "SCIM Token Hash (set as AUTH_SCIM_TOKEN): $SCIM_TOKEN_HASH"
```

Set the hash in your environment:

```bash
export AUTH_SCIM_TOKEN="$SCIM_TOKEN_HASH"
```

### Step 2: Configure SCIM in Okta

1. In the Okta admin console, go to Applications > your app > Provisioning.
2. Click "Configure API Integration".
3. Set the SCIM connector base URL to `https://auth.example.com/scim/v2`.
4. Set the authentication mode to "HTTP Header" and paste the `$SCIM_TOKEN` value.
5. Click "Test API Credentials" to verify connectivity.
6. Enable the provisioning features you need (Create Users, Update User Attributes, Deactivate Users).

### Step 3: Configure SCIM in Entra ID

1. In the Azure portal, go to Enterprise applications > your app > Provisioning.
2. Set the Provisioning Mode to "Automatic".
3. Set the Tenant URL to `https://auth.example.com/scim/v2`.
4. Set the Secret Token to the `$SCIM_TOKEN` value.
5. Click "Test Connection" to verify.
6. Configure attribute mappings (userName -> email, displayName -> name).
7. Set the provisioning scope and start provisioning.

### Step 4: Verify SCIM Connectivity

```bash
# List discovery endpoints
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  https://auth.example.com/scim/v2/ServiceProviderConfig

# List provisioned users
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  https://auth.example.com/scim/v2/Users
```

## Role Mapping Strategy

### Recommended Approach

1. **Create custom roles** that match your organization's access levels before configuring claim mappings.

```bash
# Create application-specific roles
curl -X POST https://auth.example.com/auth/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "data-scientist", "description": "Can read/write collections"}'

curl -X POST https://auth.example.com/auth/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "team-lead", "description": "Can manage collections and view users"}'
```

2. **Assign permissions** to each custom role.

```bash
curl -X PUT https://auth.example.com/auth/roles/5/permissions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permission_codenames": ["collections:read", "collections:write"]}'

curl -X PUT https://auth.example.com/auth/roles/6/permissions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permission_codenames": ["collections:read", "collections:write", "collections:manage", "users:list", "users:read"]}'
```

3. **Map IdP groups to internal roles** using claim mappings with appropriate priorities.

```bash
# Higher priority = evaluated first
# Map admin groups first (priority 30)
# Map specific teams next (priority 20)
# Map default/catch-all last (priority 10)

curl -X POST https://auth.example.com/auth/providers/1/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"claim_key": "groups", "claim_value_pattern": "Platform-Admins", "role_id": 1, "priority": 30, "is_regex": false}'

curl -X POST https://auth.example.com/auth/providers/1/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"claim_key": "groups", "claim_value_pattern": "Team-Leads", "role_id": 6, "priority": 20, "is_regex": false}'

curl -X POST https://auth.example.com/auth/providers/1/mappings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"claim_key": "groups", "claim_value_pattern": ".*", "role_id": 2, "priority": 10, "is_regex": true}'
```

### Priority Guidelines

| Priority Range | Use Case |
|---------------|----------|
| 30+ | Admin and superuser mappings |
| 20-29 | Team-specific or elevated access mappings |
| 10-19 | Default/catch-all mappings |
| 0-9 | Low-priority fallback mappings |

## Testing Checklist

After completing the integration, verify each component:

### Authentication

- [ ] Local registration creates a user with correct role
- [ ] Local login returns valid JWT tokens
- [ ] OIDC login redirects to the IdP and returns tokens after authentication
- [ ] SAML login redirects to the IdP and returns tokens after authentication
- [ ] JIT provisioning creates new users on first SSO login
- [ ] Account linking works when SSO email matches an existing local account
- [ ] Token refresh works correctly
- [ ] Logout revokes tokens

### Authorization

- [ ] Admin users can access all admin endpoints
- [ ] Non-admin users receive 403 on admin endpoints
- [ ] Custom role permissions are enforced correctly
- [ ] Permission check API returns correct results
- [ ] Collection permissions grant appropriate access levels

### SCIM

- [ ] ServiceProviderConfig returns expected capabilities
- [ ] User creation via SCIM succeeds
- [ ] User update via SCIM modifies the correct fields
- [ ] User deletion via SCIM deactivates the account and revokes tokens
- [ ] Group creation via SCIM succeeds with members
- [ ] Group deletion via SCIM removes the group

### Claim Mapping

- [ ] IdP group claims map to the correct internal roles
- [ ] Higher-priority mappings take precedence
- [ ] Regex patterns match as expected
- [ ] New role assignments appear on user's next SSO login

### Audit

- [ ] Admin actions generate audit log entries
- [ ] Audit query filters work correctly
- [ ] Audit export returns complete data

## Troubleshooting

### OIDC: "Provider not found" on SSO callback

- Verify the `provider_slug` in the callback request matches the provider's `slug` field.
- Verify the provider is active (`is_active: true`).
- Check that `AUTH_OIDC_ENABLED=true`.

### SAML: "Provider not found"

- Same as OIDC above -- check slug and active status.
- Verify `AUTH_SAML_ENABLED=true`.

### SCIM: "SCIM is not enabled" (403)

- Set `AUTH_SCIM_ENABLED=true` or use `AUTH_PROFILE=enterprise`.
- Restart the service after changing environment variables.

### SCIM: "Invalid SCIM token" (401)

- The `AUTH_SCIM_TOKEN` must be the SHA-256 hash of the bearer token, not the token itself.
- Verify the hash: `echo -n "your-token" | sha256sum` should match the value of `AUTH_SCIM_TOKEN`.

### SCIM: "SCIM token not configured" (503)

- Set `AUTH_SCIM_TOKEN` to a non-empty value (the SHA-256 hash of your bearer token).

### Permission denied (403) on role/permission endpoints

- These endpoints require specific permissions (e.g., `roles:list`, `roles:create`).
- Admin users bypass permission checks. If a non-admin user needs access, assign the appropriate permissions via a role or direct grant.

### SSO users cannot log in with password

- SSO-provisioned users have `password_hash="!sso-only"` and cannot use local login.
- SCIM-provisioned users have `password_hash="!scim-provisioned"` and also cannot use local login.
- This is by design. These users must authenticate via their identity provider.

### Account locked after failed login attempts

- The account is temporarily locked for `AUTH_ACCOUNT_LOCKOUT_DURATION_MINUTES` (default: 30 minutes).
- An admin can unlock the account by waiting for the lockout window to expire.
- The lockout threshold is controlled by `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` (default: 5 attempts).

### Token expired immediately after login

- Check that the server's clock is synchronized (NTP).
- Verify `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` is set to a reasonable value (default: 15).
- If using a load balancer, ensure all instances use the same `AUTH_JWT_SECRET`.

### Users not receiving expected roles from claim mapping

- Verify the claim key matches exactly (e.g., `groups` vs `Groups` -- case sensitive).
- Verify the claim value in the IdP's token matches the `claim_value_pattern`.
- Check mapping priorities -- only the first match per claim key is applied.
- Use the audit log to track `assign_role` events during SSO login.
