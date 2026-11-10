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
