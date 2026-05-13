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
    cors_origins: str = "*"  # comma-separated; set to specific origins in prod
    rate_limit_login: str = "10/minute"
    rate_limit_register: str = "5/minute"
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
