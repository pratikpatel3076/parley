import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_settings_raise_when_required_values_are_missing(monkeypatch) -> None:
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    message = str(exc_info.value)
    assert "SECRET_KEY" in message
    assert "DATABASE_URL" in message


def test_settings_reject_placeholder_secret(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "REPLACE_THIS_MIN_32_CHARS_BEFORE_USE")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_reject_short_secret(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "too-short")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_reject_insecure_cookie_outside_debug(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("DEBUG", "False")
    monkeypatch.setenv("COOKIE_SECURE", "False")

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "COOKIE_SECURE" in str(exc_info.value)


def test_settings_allow_insecure_cookie_in_debug(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("DEBUG", "True")
    monkeypatch.setenv("COOKIE_SECURE", "False")

    settings = Settings(_env_file=None)

    assert settings.COOKIE_SECURE is False


def test_settings_reject_empty_origin_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("DEBUG", "False")
    monkeypatch.setenv("COOKIE_SECURE", "True")
    monkeypatch.setenv("ALLOWED_ORIGINS", "[]")

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "ALLOWED_ORIGINS" in str(exc_info.value)


def test_settings_parse_origin_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("ALLOWED_ORIGINS", '["https://a.example", "https://b.example"]')

    settings = Settings(_env_file=None)

    assert settings.ALLOWED_ORIGINS == ["https://a.example", "https://b.example"]


def test_settings_reject_wildcard_origin(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("ALLOWED_ORIGINS", '["https://*.example"]')

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "wildcard" in str(exc_info.value).lower()


def test_settings_reject_origin_with_a_path(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv(
        "ALLOWED_ORIGINS",
        '["https://app.example.com/login"]',
    )

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "exact origins" in str(exc_info.value)


def test_settings_reject_origin_with_trailing_slash(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("ALLOWED_ORIGINS", '["https://app.example.com/"]')

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_reject_non_hs256_algorithm(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("ALGORITHM", "HS512")

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "HS256" in str(exc_info.value)


def test_settings_reject_access_token_lifetime_over_15_minutes(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "16")

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "15" in str(exc_info.value)


def test_settings_accept_15_minute_access_lifetime(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")

    settings = Settings(_env_file=None)

    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15


def test_settings_refresh_lifetime_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")

    settings = Settings(_env_file=None)

    assert settings.REFRESH_TOKEN_EXPIRE_DAYS == 7
