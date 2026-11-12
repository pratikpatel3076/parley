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
    # A replay of a rotated refresh token is treated as theft only after this
    # window. Inside it, the request is assumed to be a concurrent refresh from
    # another tab and is rejected without revoking anything.
    REFRESH_REUSE_GRACE_SECONDS: int = 10

    FRONTEND_URL: str = "http://localhost:5173"
    ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: ["https://localhost:5173"]
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

    @field_validator("REFRESH_REUSE_GRACE_SECONDS")
    @classmethod
    def validate_refresh_reuse_grace(cls, value: int) -> int:
        if not 0 <= value <= 60:
            raise ValueError(
                "REFRESH_REUSE_GRACE_SECONDS must be between 0 and 60."
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
        for origin in self.ALLOWED_ORIGINS:
            _validate_origin(origin, debug=self.DEBUG)
        if self.AUTH_RATE_LIMIT_ATTEMPTS < 1:
            raise ValueError("AUTH_RATE_LIMIT_ATTEMPTS must be at least 1.")
        if self.AUTH_RATE_LIMIT_WINDOW_SECONDS < 1:
            raise ValueError("AUTH_RATE_LIMIT_WINDOW_SECONDS must be at least 1.")
        if self.MAX_CIPHERTEXT_BYTES < 1:
            raise ValueError("MAX_CIPHERTEXT_BYTES must be at least 1.")
        return self


_LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1"}


def _validate_origin(origin: str, *, debug: bool) -> None:
    """Reject anything that is not an exact lowercase scheme://host[:port]."""
    if not isinstance(origin, str) or not origin.strip():
        raise ValueError(
            "ALLOWED_ORIGINS entries must be non-empty origin strings."
        )
    if origin != origin.strip():
        raise ValueError(
            "ALLOWED_ORIGINS entries must not contain leading or trailing "
            "whitespace."
        )
    if "*" in origin:
        raise ValueError("ALLOWED_ORIGINS must not contain wildcards.")
    if origin == "null":
        raise ValueError(
            'ALLOWED_ORIGINS must not contain the literal "null" origin.'
        )

    scheme, separator, remainder = origin.partition("://")
    if separator != "://" or scheme not in {"http", "https"}:
        raise ValueError(
            "ALLOWED_ORIGINS entries must start with an exact lowercase "
            "http:// or https:// scheme."
        )
    if remainder != remainder.strip() or not remainder:
        raise ValueError(
            "ALLOWED_ORIGINS entries must contain a host and no whitespace."
        )

    try:
        parts = urlsplit(origin)
        port = parts.port
    except ValueError:
        raise ValueError(
            "ALLOWED_ORIGINS entries must contain a valid host and port."
        ) from None

    canonical = f"{parts.scheme}://{parts.netloc}"
    if (
        parts.scheme != scheme
        or not parts.netloc
        or parts.netloc.endswith(":")
        or parts.netloc != parts.netloc.lower()
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
        or origin != canonical
    ):
        raise ValueError(
            "ALLOWED_ORIGINS entries must be exact origins in lowercase with "
            "scheme, host, and optional port, and no path, query, or "
            "fragment (for example https://app.example.com)."
        )
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError(
            "ALLOWED_ORIGINS entries must use a port between 1 and 65535."
        )
    if scheme == "http" and not (
        debug and parts.hostname in _LOCAL_HTTP_HOSTS
    ):
        raise ValueError(
            "http:// origins are allowed only when DEBUG=True and the host "
            "is localhost or 127.0.0.1."
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
