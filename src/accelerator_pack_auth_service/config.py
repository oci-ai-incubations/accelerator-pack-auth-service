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

    # JWT
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
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

    model_config = {"env_prefix": "AUTH_"}

    def model_post_init(self, __context):
        """Apply profile presets if profile is not 'custom'."""
        if self.profile in PROFILE_PRESETS:
            preset = PROFILE_PRESETS[self.profile]
            for key, value in preset.items():
                # Only apply preset if env var wasn't explicitly set
                if key not in (self.model_fields_set or set()):
                    object.__setattr__(self, key, value)


settings = Settings()
