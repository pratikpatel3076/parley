"""Tests for the development-only key-swap simulation script."""

from __future__ import annotations

import base64
import importlib.util
import io
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "simulate_key_swap.py"


def _load_script() -> Any:
    spec = importlib.util.spec_from_file_location("simulate_key_swap", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


simulate_key_swap = _load_script()


@dataclass
class FakeSettings:
    DATABASE_URL: str
    DEBUG: bool = True
    APP_ENV: str = "test"


def _make_database(path: Path, key: bytes, *, text: bool = False) -> None:
    column_type = "TEXT" if text else "BLOB"
    stored: bytes | str = (
        base64.b64encode(key).decode("ascii") if text else key
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE users ("
            "id TEXT PRIMARY KEY, "
            "username TEXT NOT NULL UNIQUE, "
            f"public_key {column_type} NOT NULL)"
        )
        connection.execute(
            "INSERT INTO users (id, username, public_key) VALUES (?, ?, ?)",
            ("user-1", "alice", stored),
        )


def _read_key(path: Path) -> bytes | str:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT public_key FROM users WHERE username = ?", ("alice",)
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return row[0]


def _run(
    argv: list[str],
    settings: FakeSettings,
    state_dir: Path,
) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    code = simulate_key_swap.main(
        argv,
        settings_obj=settings,
        state_dir=state_dir,
        out=out,
        err=err,
    )
    return code, out.getvalue(), err.getvalue()


def _database_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


ORIGINAL_KEY = bytes(range(32))


def test_swap_replaces_the_stored_key(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database))

    code, out, err = _run(["swap", "alice", "--yes"], settings, state_dir)

    assert code == 0, err
    assert "Replacement public key:" in out
    assert "Updated users.public_key for alice." in out
    changed = _read_key(database)
    assert isinstance(changed, bytes)
    assert len(changed) == 32
    assert changed != ORIGINAL_KEY
    saved = state_dir / "parley-key-swap-alice.json"
    assert saved.exists()


def test_restore_puts_the_original_key_back(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database))

    assert _run(["swap", "alice", "--yes"], settings, state_dir)[0] == 0
    assert _read_key(database) != ORIGINAL_KEY

    code, out, err = _run(["restore", "alice", "--yes"], settings, state_dir)

    assert code == 0, err
    assert "Restored the original public key for alice." in out
    assert _read_key(database) == ORIGINAL_KEY
    assert not (state_dir / "parley-key-swap-alice.json").exists()


def test_text_key_storage_round_trips(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY, text=True)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database))

    assert _run(["swap", "alice", "--yes"], settings, state_dir)[0] == 0
    swapped = _read_key(database)
    assert isinstance(swapped, str)
    assert base64.b64decode(swapped) != ORIGINAL_KEY

    assert _run(["restore", "alice", "--yes"], settings, state_dir)[0] == 0
    assert _read_key(database) == base64.b64encode(ORIGINAL_KEY).decode("ascii")


def test_swap_refuses_when_debug_is_false(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database), DEBUG=False)

    code, _out, err = _run(["swap", "alice", "--yes"], settings, state_dir)

    assert code == 1
    assert "DEBUG must be True" in err
    assert _read_key(database) == ORIGINAL_KEY
    assert not (state_dir / "parley-key-swap-alice.json").exists()


def test_swap_refuses_in_production(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database), APP_ENV="production")

    code, _out, err = _run(["swap", "alice", "--yes"], settings, state_dir)

    assert code == 1
    assert "APP_ENV must not be production" in err
    assert _read_key(database) == ORIGINAL_KEY


def test_swap_refuses_without_yes(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database))

    code, out, err = _run(["swap", "alice"], settings, state_dir)

    assert code == 1, err
    assert "No changes made. Re-run with --yes to apply." in out
    assert _read_key(database) == ORIGINAL_KEY
    assert not (state_dir / "parley-key-swap-alice.json").exists()


def test_refuses_non_sqlite_url(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings("postgresql+asyncpg://user:pass@localhost/parley")

    code, _out, err = _run(["swap", "alice", "--yes"], settings, state_dir)

    assert code == 1
    assert "only SQLite DATABASE_URL values are supported" in err
    assert _read_key(database) == ORIGINAL_KEY


def test_restore_refuses_an_unexpected_current_key(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database))

    assert _run(["swap", "alice", "--yes"], settings, state_dir)[0] == 0

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE users SET public_key = ? WHERE username = ?",
            (b"x" * 32, "alice"),
        )

    code, _out, err = _run(["restore", "alice", "--yes"], settings, state_dir)

    assert code == 1
    assert "refusing to overwrite an unexpected value" in err
    assert _read_key(database) == b"x" * 32


def test_restore_refuses_without_a_saved_original(tmp_path: Path) -> None:
    database = tmp_path / "parley.db"
    _make_database(database, ORIGINAL_KEY)
    state_dir = tmp_path / "state"
    settings = FakeSettings(_database_url(database))

    code, _out, err = _run(["restore", "alice", "--yes"], settings, state_dir)

    assert code == 1
    assert "no saved original" in err
    assert _read_key(database) == ORIGINAL_KEY
