from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables and .env.

    SECRET_KEY and DATABASE_URL have no defaults on purpose. Importing this
    module raises a validation error when either one is missing, so the server
    cannot start with an undocumented fallback secret.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "Parley"
    DEBUG: bool = False
    SECRET_KEY: str
    DATABASE_URL: str

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    FRONTEND_URL: str = "http://localhost:5173"
    ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )
    COOKIE_SECURE: bool = True
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters. Generate one with "
                "python -c \"import secrets; print(secrets.token_urlsafe(48))\"."
            )
        lowered = value.strip().lower()
        if lowered.startswith("replace") or lowered in {
            "change-me",
            "changeme",
            "change_this",
            "secret",
            "changethis",
        }:
            raise ValueError("SECRET_KEY must not be a placeholder value.")
        return value

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("DATABASE_URL must be a non-empty connection string.")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
