import json

import pytest
from pydantic import ValidationError

from app.core.config import PRODUCTION_BCRYPT_ROUNDS, Settings


def _settings_with_origins(
    monkeypatch,
    origins: list[str],
    *,
    debug: bool = False,
) -> Settings:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("DEBUG", "True" if debug else "False")
    monkeypatch.setenv("COOKIE_SECURE", "True")
    monkeypatch.setenv("ALLOWED_ORIGINS", json.dumps(origins))
    return Settings(_env_file=None)


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


@pytest.mark.parametrize(
    "origin",
    [
        "https://app.example.com/",
        "https://app.example.com/login",
        "https://app.example.com?debug=1",
        "https://app.example.com#section",
        "https://*.example.com",
        "null",
        "NULL",
        "HTTPS://app.example.com",
        "https://App.Example.com",
        "",
        "   ",
        " https://app.example.com",
        "https://app.example.com ",
        "https://app.example.com:70000",
        "https://app.example.com:",
        "https://user:pass@app.example.com",
        "ftp://app.example.com",
        "app.example.com",
    ],
)
def test_settings_reject_malformed_origins(monkeypatch, origin: str) -> None:
    with pytest.raises(ValidationError):
        _settings_with_origins(monkeypatch, [origin])


@pytest.mark.parametrize(
    "origin",
    ["http://app.example.com", "http://localhost:5173", "http://127.0.0.1:8000"],
)
def test_settings_reject_http_origins_outside_debug(monkeypatch, origin: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _settings_with_origins(monkeypatch, [origin])

    message = str(exc_info.value)
    assert "DEBUG=True" in message
    assert "localhost or 127.0.0.1" in message


@pytest.mark.parametrize(
    "origin",
    ["http://localhost:5173", "http://127.0.0.1:8000"],
)
def test_settings_accept_http_localhost_in_debug(monkeypatch, origin: str) -> None:
    settings = _settings_with_origins(monkeypatch, [origin], debug=True)

    assert settings.ALLOWED_ORIGINS == [origin]


@pytest.mark.parametrize(
    "origin",
    [
        "https://app.example.com",
        "https://app.example.com:8443",
        "https://localhost:5173",
        "https://127.0.0.1:8443",
    ],
)
def test_settings_accept_exact_https_origins(monkeypatch, origin: str) -> None:
    settings = _settings_with_origins(monkeypatch, [origin])

    assert settings.ALLOWED_ORIGINS == [origin]


def test_settings_accept_multiple_mixed_valid_origins(monkeypatch) -> None:
    origins = ["https://app.example.com", "http://localhost:5173"]

    settings = _settings_with_origins(monkeypatch, origins, debug=True)

    assert settings.ALLOWED_ORIGINS == origins


@pytest.mark.parametrize("value", ["-1", "61", "120"])
def test_settings_reject_reuse_grace_out_of_range(monkeypatch, value: str) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("REFRESH_REUSE_GRACE_SECONDS", value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "REFRESH_REUSE_GRACE_SECONDS" in str(exc_info.value)


@pytest.mark.parametrize(("value", "expected"), [("0", 0), ("10", 10), ("60", 60)])
def test_settings_accept_reuse_grace_in_range(
    monkeypatch, value: str, expected: int
) -> None:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("REFRESH_REUSE_GRACE_SECONDS", value)

    settings = Settings(_env_file=None)

    assert settings.REFRESH_REUSE_GRACE_SECONDS == expected


def _settings_with_bcrypt_env(
    monkeypatch,
    *,
    app_env: str | None,
    rounds: str | None,
) -> Settings:
    monkeypatch.setenv("SECRET_KEY", "test-" + "x" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    monkeypatch.setenv("DEBUG", "False")
    monkeypatch.setenv("COOKIE_SECURE", "True")
    if app_env is None:
        monkeypatch.delenv("APP_ENV", raising=False)
    else:
        monkeypatch.setenv("APP_ENV", app_env)
    if rounds is None:
        monkeypatch.delenv("BCRYPT_ROUNDS", raising=False)
    else:
        monkeypatch.setenv("BCRYPT_ROUNDS", rounds)
    return Settings(_env_file=None)


def test_bcrypt_rounds_default_to_the_production_cost(monkeypatch) -> None:
    settings = _settings_with_bcrypt_env(monkeypatch, app_env=None, rounds=None)

    assert settings.BCRYPT_ROUNDS == PRODUCTION_BCRYPT_ROUNDS == 12
    assert settings.APP_ENV == "production"


def test_settings_refuse_reduced_bcrypt_rounds_outside_test_profile(
    monkeypatch,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _settings_with_bcrypt_env(monkeypatch, app_env="production", rounds="4")

    message = str(exc_info.value)
    assert "BCRYPT_ROUNDS=4" in message
    assert "production cost of 12" in message
    assert "APP_ENV=test" in message


def test_settings_accept_reduced_bcrypt_rounds_in_test_profile(monkeypatch) -> None:
    settings = _settings_with_bcrypt_env(monkeypatch, app_env="test", rounds="4")

    assert settings.BCRYPT_ROUNDS == 4
    assert settings.APP_ENV == "test"


@pytest.mark.parametrize("app_env", ["staging", "development", "TEST", ""])
def test_settings_reject_unknown_app_env(monkeypatch, app_env: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _settings_with_bcrypt_env(monkeypatch, app_env=app_env, rounds="4")

    assert "APP_ENV must be production or test" in str(exc_info.value)


@pytest.mark.parametrize("rounds", ["3", "32"])
def test_settings_reject_out_of_range_bcrypt_rounds(
    monkeypatch, rounds: str
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _settings_with_bcrypt_env(monkeypatch, app_env="test", rounds=rounds)

    assert "BCRYPT_ROUNDS must be between 4 and 31" in str(exc_info.value)


def test_dummy_auth_hash_uses_the_same_rounds_as_real_hashes() -> None:
    import base64

    from app.core.config import settings
    from app.core.security import dummy_auth_hash, hash_auth_secret

    def cost(auth_hash: str) -> int:
        return int(auth_hash.split("$")[2])

    auth_secret = base64.b64encode(b"\x11" * 32).decode("ascii")
    real_hash = hash_auth_secret(auth_secret)

    assert cost(dummy_auth_hash()) == cost(real_hash) == settings.BCRYPT_ROUNDS
