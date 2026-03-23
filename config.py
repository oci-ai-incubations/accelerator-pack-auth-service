from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite+aiosqlite:///./auth.db"
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    # First registered user auto-promoted to admin
    auto_admin_first_user: bool = True

    model_config = {"env_prefix": "AUTH_"}


settings = Settings()
