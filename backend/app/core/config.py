from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
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

    AUTH_RATE_LIMIT_ATTEMPTS: int = 10
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60
    MAX_CIPHERTEXT_BYTES: int = 65_536

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

    @field_validator("ALGORITHM")
    @classmethod
    def validate_algorithm(cls, value: str) -> str:
        if value != "HS256":
            raise ValueError("ALGORITHM must be HS256.")
        return value

    @field_validator("ACCESS_TOKEN_EXPIRE_MINUTES")
    @classmethod
    def validate_access_token_lifetime(cls, value: int) -> int:
        if not 1 <= value <= 15:
            raise ValueError(
                "ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 15."
            )
        return value

    @field_validator("REFRESH_TOKEN_EXPIRE_DAYS")
    @classmethod
    def validate_refresh_token_lifetime(cls, value: int) -> int:
        if value < 1:
            raise ValueError("REFRESH_TOKEN_EXPIRE_DAYS must be at least 1.")
        return value

    @field_validator("ALLOWED_ORIGINS")
    @classmethod
    def validate_allowed_origins(cls, value: list[str]) -> list[str]:
        for origin in value:
            if "*" in origin:
                raise ValueError("ALLOWED_ORIGINS must not contain wildcards.")
            parts = urlsplit(origin)
            canonical = f"{parts.scheme}://{parts.netloc}"
            if (
                parts.scheme not in {"http", "https"}
                or not parts.netloc
                or parts.path
                or parts.query
                or parts.fragment
                or parts.username
                or parts.password
                or origin != canonical
            ):
                raise ValueError(
                    "ALLOWED_ORIGINS entries must be exact origins with "
                    "scheme, host, and optional port, and no path "
                    "(for example https://app.example.com)."
                )
        return value

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if not self.DEBUG and not self.COOKIE_SECURE:
            raise ValueError(
                "COOKIE_SECURE may be disabled only when DEBUG=True. "
                "Set COOKIE_SECURE=True outside local development."
            )
        if not self.ALLOWED_ORIGINS:
            raise ValueError("ALLOWED_ORIGINS must contain at least one origin.")
        if self.AUTH_RATE_LIMIT_ATTEMPTS < 1:
            raise ValueError("AUTH_RATE_LIMIT_ATTEMPTS must be at least 1.")
        if self.AUTH_RATE_LIMIT_WINDOW_SECONDS < 1:
            raise ValueError("AUTH_RATE_LIMIT_WINDOW_SECONDS must be at least 1.")
        if self.MAX_CIPHERTEXT_BYTES < 1:
            raise ValueError("MAX_CIPHERTEXT_BYTES must be at least 1.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
