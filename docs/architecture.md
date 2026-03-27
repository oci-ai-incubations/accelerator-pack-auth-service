# Architecture

This document describes the system architecture, authentication and authorization flows, and deployment topology for the Enterprise Auth Service.

## High-Level Architecture

The auth service operates as a sidecar microservice alongside the main application frontend and backend. It owns all identity, authentication, and authorization concerns.

```mermaid
graph TB
    Browser[Browser / Client]
    Frontend[Frontend App]
    Backend[Backend API]
    AuthService[Auth Service<br/>:8080]
    DB[(Database<br/>SQLite / PostgreSQL / Oracle 26ai)]
    IdP[External IdP<br/>Okta / Entra ID / Auth0]

    Browser --> Frontend
    Frontend --> AuthService
    Frontend --> Backend
    Backend --> AuthService
    AuthService --> DB
    AuthService <--> IdP

    style AuthService fill:#2d5aa0,color:#fff
    style DB fill:#4a4a4a,color:#fff
    style IdP fill:#6b4c9a,color:#fff
```

### Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| **Auth Service** | User registration, login, JWT issuance, token refresh/revocation, RBAC evaluation, SSO (OIDC/SAML), SCIM provisioning, audit logging |
| **Frontend** | Stores JWT in memory/localStorage, attaches `Authorization: Bearer` header to API calls, redirects to IdP for SSO |
| **Backend** | Validates JWT signature and expiry, calls auth service for permission checks when needed |
| **Database** | Stores users, roles, permissions, tokens, providers, groups, and audit logs |
| **External IdP** | Authenticates users via OIDC or SAML, pushes user/group changes via SCIM |

## Authentication Flows

### Local Authentication

```mermaid
sequenceDiagram
    participant Client
    participant AuthService as Auth Service
    participant DB as Database

    Client->>AuthService: POST /auth/register<br/>{email, password, name}
    AuthService->>DB: Check email uniqueness
    AuthService->>DB: Check user count (auto-admin)
    AuthService->>DB: Insert user (bcrypt hash)
    AuthService->>DB: Store refresh token (SHA-256 hash)
    AuthService->>Client: {access_token, refresh_token, user}

    Note over Client,AuthService: Subsequent login

    Client->>AuthService: POST /auth/login<br/>{email, password}
    AuthService->>DB: Check account lockout
    AuthService->>DB: Lookup user by email
    AuthService->>AuthService: Verify bcrypt hash
    AuthService->>DB: Clear failed attempts
    AuthService->>DB: Enforce session limit
    AuthService->>DB: Store refresh token
    AuthService->>Client: {access_token, refresh_token, user}
```

### OIDC Authentication

```mermaid
sequenceDiagram
    participant Browser
    participant Frontend
    participant IdP as OIDC Provider
    participant AuthService as Auth Service
    participant DB as Database

    Browser->>Frontend: Click SSO login
    Frontend->>IdP: Redirect to /authorize
    IdP->>Browser: Login page
    Browser->>IdP: Submit credentials
    IdP->>Frontend: Redirect with auth code
    Frontend->>IdP: Exchange code for tokens
    IdP->>Frontend: ID token + access token
    Frontend->>AuthService: POST /auth/sso/callback<br/>{provider_slug, external_id, email, name, claims}
    AuthService->>DB: Lookup provider by slug
    AuthService->>DB: Check external identity
    alt New user
        AuthService->>DB: Create user (role=user)
        AuthService->>DB: Create external identity link
    else Existing email
        AuthService->>DB: Link external identity to existing user
    else Returning SSO user
        AuthService->>DB: Update last_login_at
    end
    AuthService->>DB: Evaluate claim-to-role mappings
    AuthService->>DB: Assign matched roles
    AuthService->>DB: Issue internal tokens
    AuthService->>Frontend: {access_token, refresh_token, user}
    Frontend->>Browser: Store tokens, load app
```

### SAML Authentication

```mermaid
sequenceDiagram
    participant Browser
    participant Frontend
    participant IdP as SAML IdP
    participant AuthService as Auth Service
    participant DB as Database

    Browser->>Frontend: Click SSO login
    Frontend->>IdP: SAML AuthnRequest (redirect)
    IdP->>Browser: Login page
    Browser->>IdP: Submit credentials
    IdP->>Frontend: SAML Response (POST to ACS)
    Frontend->>Frontend: Validate SAML assertion
    Frontend->>AuthService: POST /auth/sso/callback<br/>{provider_slug, external_id, email, name, claims}
    AuthService->>DB: JIT provision (same as OIDC)
    AuthService->>DB: Apply claim mappings
    AuthService->>DB: Issue internal tokens
    AuthService->>Frontend: {access_token, refresh_token, user}
```

## Authorization Flow

```mermaid
flowchart TD
    Request[API Request with JWT]
    Decode[Decode JWT]
    Blacklist{Token<br/>blacklisted?}
    LoadUser[Load user from DB]
    Active{User<br/>active?}
    AdminCheck{User role<br/>= admin?}
    RolePerms{Role-based<br/>permission?}
    LegacyRole{Legacy role<br/>mapping?}
    DirectGrant{Direct<br/>grant?}
    Ownership{Resource<br/>owner?}
    Allow[Allow]
    Deny[Deny 403]
    Unauthorized[Deny 401]

    Request --> Decode
    Decode --> Blacklist
    Blacklist -->|Yes| Unauthorized
    Blacklist -->|No| LoadUser
    LoadUser --> Active
    Active -->|No| Unauthorized
    Active -->|Yes| AdminCheck
    AdminCheck -->|Yes| Allow
    AdminCheck -->|No| RolePerms
    RolePerms -->|Yes| Allow
    RolePerms -->|No| LegacyRole
    LegacyRole -->|Yes| Allow
    LegacyRole -->|No| DirectGrant
    DirectGrant -->|Yes| Allow
    DirectGrant -->|No| Ownership
    Ownership -->|Yes| Allow
    Ownership -->|No| Deny

    style Allow fill:#2d7d2d,color:#fff
    style Deny fill:#b22222,color:#fff
    style Unauthorized fill:#b22222,color:#fff
```

## SCIM Provisioning Flow

```mermaid
sequenceDiagram
    participant IdP as Identity Provider
    participant AuthService as Auth Service
    participant DB as Database

    Note over IdP,AuthService: User Lifecycle

    IdP->>AuthService: POST /scim/v2/Users<br/>(Bearer token auth)
    AuthService->>DB: Create user (role=user, active=true)
    AuthService->>IdP: 201 Created (SCIM User)

    IdP->>AuthService: PUT /scim/v2/Users/{id}<br/>{displayName, active}
    AuthService->>DB: Update user fields
    AuthService->>IdP: 200 OK (SCIM User)

    IdP->>AuthService: DELETE /scim/v2/Users/{id}
    AuthService->>DB: Set is_active=false
    AuthService->>DB: Revoke all refresh tokens
    AuthService->>IdP: 204 No Content

    Note over IdP,AuthService: Group Lifecycle

    IdP->>AuthService: POST /scim/v2/Groups<br/>{displayName, members}
    AuthService->>DB: Create group (source=scim)
    AuthService->>DB: Add group memberships
    AuthService->>IdP: 201 Created (SCIM Group)

    IdP->>AuthService: DELETE /scim/v2/Groups/{id}
    AuthService->>DB: Delete group + memberships (cascade)
    AuthService->>IdP: 204 No Content
```

## Enterprise Integration Example

This diagram shows a typical enterprise deployment where Okta is used as the identity provider with both OIDC (for interactive login) and SCIM (for directory sync).

```mermaid
graph LR
    subgraph Enterprise Network
        Okta[Okta]
    end

    subgraph OKE Cluster
        Ingress[Ingress Controller]
        FE[Frontend Pod]
        BE[Backend Pod]
        Auth[Auth Service Pod]
        DB[(PostgreSQL / Oracle)]
    end

    Okta -->|OIDC| Ingress
    Okta -->|SCIM| Ingress
    Ingress --> FE
    Ingress --> Auth
    FE --> Auth
    FE --> BE
    BE --> Auth
    Auth --> DB

    style Okta fill:#6b4c9a,color:#fff
    style Auth fill:#2d5aa0,color:#fff
    style DB fill:#4a4a4a,color:#fff
```

**Flow:**

1. **SCIM (background)**: Okta pushes user and group changes to `/scim/v2/*` endpoints. Users are created/deactivated automatically. Groups are synced.
2. **OIDC (interactive)**: Users click "Sign in with Okta" in the frontend. The OIDC flow authenticates the user, and the auth service issues internal tokens via JIT provisioning.
3. **Claim mapping**: Okta group memberships (sent as claims) are mapped to internal RBAC roles. For example, the "Platform-Admin" Okta group maps to the internal `admin` role.
4. **Authorization**: The backend validates JWT tokens and calls the permission check API when fine-grained access control is needed.

## Deployment Topology on OKE

```mermaid
graph TB
    subgraph OKE Cluster
        subgraph Namespace: app
            FE[Frontend<br/>Deployment<br/>replicas: 2]
            BE[Backend<br/>Deployment<br/>replicas: 2]
            Auth[Auth Service<br/>Deployment<br/>replicas: 2]
        end

        subgraph Namespace: data
            PG[(PostgreSQL<br/>StatefulSet)]
        end

        Ingress[NGINX Ingress<br/>Controller]
        FE_SVC[frontend-svc]
        BE_SVC[backend-svc]
        Auth_SVC[auth-service-svc<br/>:8080]
        PG_SVC[postgres-svc<br/>:5432]
    end

    LB[OCI Load Balancer]

    LB --> Ingress
    Ingress --> FE_SVC --> FE
    Ingress --> BE_SVC --> BE
    Ingress --> Auth_SVC --> Auth
    Auth --> PG_SVC --> PG

    style Auth fill:#2d5aa0,color:#fff
    style PG fill:#4a4a4a,color:#fff
    style LB fill:#e67e22,color:#fff
```

### Key Design Decisions

- **Stateless service**: The auth service stores all state in the database. Horizontal scaling is achieved by adding replicas.
- **Sidecar pattern**: The auth service runs alongside the application rather than as a centralized gateway, reducing latency and blast radius.
- **Token-based auth**: JWTs are self-contained and can be validated by any service without calling back to the auth service. Only permission checks and token revocation require a call to the auth service.
- **Feature flags**: Unused features (OIDC, SAML, SCIM) can be disabled to reduce attack surface in simpler deployments.
- **Database flexibility**: The same codebase supports SQLite (development), PostgreSQL (standard production), and Oracle 26ai (enterprise production) via auto-detection.
