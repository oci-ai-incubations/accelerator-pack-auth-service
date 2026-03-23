from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database — supports sqlite+aiosqlite://, postgresql+asyncpg://, oracle+oracledb://
    database_url: str = "sqlite+aiosqlite:///./auth.db"

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
