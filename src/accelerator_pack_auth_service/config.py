from pydantic_settings import BaseSettings

# Profile presets: which features are enabled by default per profile
PROFILE_PRESETS = {
    "minimal": {
        "local_auth_enabled": True,
        "oidc_enabled": False,
        "saml_enabled": False,
        "scim_enabled": False,
        "audit_enabled": False,
    },
    "standard": {
        "local_auth_enabled": True,
        "oidc_enabled": True,
        "saml_enabled": False,
        "scim_enabled": False,
        "audit_enabled": True,
    },
    "enterprise": {
        "local_auth_enabled": True,
        "oidc_enabled": True,
        "saml_enabled": True,
        "scim_enabled": True,
        "audit_enabled": True,
    },
}


class Settings(BaseSettings):
    # Database — supports sqlite+aiosqlite://, postgresql+asyncpg://
    # For Oracle 26ai, set database_type=oracle and provide oracle_* vars
    database_url: str = "sqlite+aiosqlite:///./auth.db"
    database_type: str = "auto"  # auto, sqlite, postgres, oracle

    # Oracle 26ai connection (used when database_type=oracle or auto-detected)
    oracle_connection_string: str = ""  # e.g., tcps://host:1521/service
    oracle_user: str = ""
    oracle_password: str = ""

    # JWT (RS256 only — signing keys live in the signing_keys table).
    # issuer_url is the public origin of this auth-service (e.g.
    # https://pack.example.com/auth); it goes into every token's `iss` claim
    # and the OIDC discovery doc. Required when token issuance is enabled
    # (local_auth_enabled or oidc_enabled); validated in `model_post_init`.
    issuer_url: str = ""
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Security
    bcrypt_rounds: int = 12
    # Comma-separated list of allowed CORS origins. Fail-closed default —
    # operators must explicitly enumerate trusted origins (matches the
    # pack-BE convention; AUTH_CORS_ORIGINS is plumbed from TF in
    # ai-accelerator-starter-packs/auth-locals.tf). A wildcard is detected
    # at middleware setup and forces allow_credentials=False to satisfy
    # the CORS spec.
    cors_origins: str = ""
    # When false, emit production security headers (HSTS, etc.) and disable
    # OpenAPI doc surfaces per security-standards.md. When true (dev),
    # suppress HSTS so a self-signed cluster cert doesn't pin the browser
    # into refusing the host on the next visit.
    debug: bool = False
    rate_limit_login: str = "10/minute"
    rate_limit_register: str = "5/minute"
    # Refresh tokens and SSO callback exchanges are the post-login
    # equivalent of /login — protect them at the same rate.
    rate_limit_refresh: str = "10/minute"
    rate_limit_sso_token: str = "10/minute"
    rate_limit_audit: str = "20/minute"
    rate_limit_audit_export: str = "5/minute"
    # OAuth2 token endpoint is a favored credential-stuffing target — stricter
    # per-IP limit than other authenticated endpoints. Per-client limits
    # belong in spec 003 / a follow-up.
    rate_limit_oauth_token: str = "60/minute"

    # OAuth2 client_credentials grant. Master switch lets ops disable the
    # entire flow if a deployment doesn't issue service accounts.
    client_credentials_enabled: bool = True
    # Strict scope-grant mode (spec 003). RFC 6749 §3.3 defaults to lenient:
    # when a request asks for a partially-allowed set, the server issues a
    # token covering the intersection. Flipping this to true rejects the
    # whole request with ``invalid_scope`` instead — useful for integrators
    # who prefer loud failures over silently-narrower tokens. Default
    # lenient because that's the RFC default and what most clients expect.
    strict_scopes: bool = False
    # Client tokens are typically longer-lived than user access tokens —
    # clients re-fetch using the same credentials with no human in the loop.
    client_token_expire_minutes: int = 60
    # Soft cap on service accounts per owner — prevents accidental sprawl.
    client_max_per_owner: int = 20
    # Env-seeded service account (machine identity for downstream ETL/workers).
    # When both id and secret are set, the lifespan idempotently upserts a
    # ServiceAccount with this client_id + bcrypt-hashed secret on startup, so
    # deployments don't need a human to register/create a client first. Scopes
    # are space-separated. Env: AUTH_BOOTSTRAP_CLIENT_ID/SECRET/SCOPES.
    bootstrap_client_id: str = ""
    bootstrap_client_secret: str = ""
    bootstrap_client_scopes: str = ""
    account_lockout_threshold: int = 5
    account_lockout_duration_minutes: int = 30
    max_concurrent_sessions: int = 5

    # Feature flags
    local_auth_enabled: bool = True
    oidc_enabled: bool = False
    saml_enabled: bool = False
    scim_enabled: bool = False
    scim_token: str = ""  # Hashed SCIM bearer token for provisioning
    audit_enabled: bool = True
    audit_retention_days: int = 90

    # SSO
    sso_redirect_base_url: str = ""  # e.g., https://app.example.com

    # Profile: minimal|standard|enterprise|custom
    profile: str = "custom"

    # First registered user auto-promoted to admin
    auto_admin_first_user: bool = True

    # Pack-extensible RBAC: selects which PackAuthModel seeds the DB on first
    # deploy and gates runtime require_pack_permission checks. See
    # pack_models/registry.py for known packs. Default "base" = admin + user
    # only (no pack-specific perms); existing paas_rag deploys MUST set
    # AUTH_PACK=paas_rag after upgrading past this change.
    # Field is `pack` so the env_prefix yields `AUTH_PACK`.
    pack: str = "base"

    model_config = {"env_prefix": "AUTH_"}

    def model_post_init(self, __context):
        """Apply profile presets and validate issuer configuration."""
        if self.profile in PROFILE_PRESETS:
            preset = PROFILE_PRESETS[self.profile]
            for key, value in preset.items():
                # Only apply preset if env var wasn't explicitly set
                if key not in (self.model_fields_set or set()):
                    object.__setattr__(self, key, value)
        if not self.issuer_url and (self.local_auth_enabled or self.oidc_enabled):
            raise ValueError("AUTH_ISSUER_URL must be set when token issuance is enabled.")


settings = Settings()
