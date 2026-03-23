from pydantic_settings import BaseSettings


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

    # First registered user auto-promoted to admin
    auto_admin_first_user: bool = True

    model_config = {"env_prefix": "AUTH_"}


settings = Settings()
