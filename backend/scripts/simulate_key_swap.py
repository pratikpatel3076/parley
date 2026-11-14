#!/usr/bin/env python3
"""Simulate a malicious key-directory server against a local development DB.

This is a development-only helper. It replaces a user's stored public key with a
random 32-byte key so the client's key-change banner can be exercised without a
second account. The original key is saved to a JSON file in the system temp
directory so ``restore`` can put it back.

The script refuses to run unless ``DEBUG=True`` and ``APP_ENV`` is not
``production``. It supports SQLite only and requires an explicit ``--yes``.

Usage (from the backend directory):

    python scripts/simulate_key_swap.py swap <username> --yes
    python scripts/simulate_key_swap.py restore <username> --yes

The real schema stores ``users.public_key`` as a 32-byte BLOB. Some local
databases may hold the same key as base64 text; both forms are detected and
written back in the form that was found.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import secrets
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence, TextIO

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

KEY_BYTES = 32
USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{3,32}$")
STATE_VERSION = 1


class Refusal(Exception):
    """A condition that must stop the script before it changes anything."""


def _validate_username(username: str) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise Refusal(
            "username must be 3-32 lowercase ASCII characters matching "
            "^[a-z0-9_]{3,32}$"
        )


def _database_path(database_url: str) -> Path:
    try:
        url = make_url(database_url)
    except ArgumentError:
        raise Refusal("DATABASE_URL is not a valid SQLAlchemy URL") from None
    if url.get_backend_name() != "sqlite":
        raise Refusal(
            f"only SQLite DATABASE_URL values are supported; got "
            f"{url.get_backend_name()!r}"
        )
    if not url.database or url.database == ":memory:":
        raise Refusal("an in-memory SQLite database has no file to edit")
    return Path(url.database)


def _state_path(username: str, state_dir: Path | None) -> Path:
    directory = Path(state_dir) if state_dir is not None else Path(tempfile.gettempdir())
    return directory / f"parley-key-swap-{username}.json"


def _read_user(
    connection: sqlite3.Connection, username: str
) -> tuple[str, str, bytes]:
    row = connection.execute(
        "SELECT id, public_key FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        raise Refusal(f"no user named {username!r} in the database")
    user_id, stored = row
    if stored is None:
        raise Refusal(f"user {username!r} has no stored public key")
    if isinstance(stored, memoryview):
        stored = bytes(stored)
    if isinstance(stored, bytes):
        storage = "blob"
        key = stored
    elif isinstance(stored, str):
        storage = "text"
        try:
            key = base64.b64decode(stored, validate=True)
        except (binascii.Error, ValueError):
            raise Refusal(
                f"user {username!r} has a text public key that is not valid base64"
            ) from None
    else:
        raise Refusal(
            f"user {username!r} has an unsupported public_key storage type: "
            f"{type(stored).__name__}"
        )
    if len(key) != KEY_BYTES:
        raise Refusal(
            f"user {username!r} has a {len(key)}-byte public key; expected "
            f"{KEY_BYTES} bytes"
        )
    return str(user_id), storage, key


def _stored_value(storage: str, key: bytes) -> bytes | str:
    if storage == "blob":
        return key
    return base64.b64encode(key).decode("ascii")


def _key_text(storage: str, key: bytes) -> str:
    if storage == "blob":
        return f"{key.hex()} (32 bytes, blob)"
    return f"{base64.b64encode(key).decode('ascii')} (32 bytes, text/base64)"


def _write_state(
    path: Path,
    *,
    username: str,
    database_path: Path,
    storage: str,
    original: bytes,
    replacement: bytes,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": STATE_VERSION,
        "username": username,
        "database_path": str(database_path.resolve()),
        "storage": storage,
        "original": base64.b64encode(original).decode("ascii"),
        "replacement": base64.b64encode(replacement).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _load_state(
    path: Path, username: str, database_path: Path
) -> tuple[str, bytes, bytes]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"could not read the saved original at {path}: {exc}") from None
    if not isinstance(payload, dict):
        raise Refusal(f"{path} does not contain a saved-original object")
    if payload.get("version") != STATE_VERSION:
        raise Refusal(f"unsupported saved-original version in {path}")
    if payload.get("username") != username:
        raise Refusal(f"{path} belongs to a different username")
    saved_database = payload.get("database_path")
    if not isinstance(saved_database, str) or (
        Path(saved_database).resolve() != database_path.resolve()
    ):
        raise Refusal(f"{path} was saved for a different database")
    storage = payload.get("storage")
    if storage not in {"blob", "text"}:
        raise Refusal(f"{path} has an invalid storage type")
    try:
        original = base64.b64decode(payload["original"], validate=True)
        replacement = base64.b64decode(payload["replacement"], validate=True)
    except (KeyError, TypeError, binascii.Error, ValueError):
        raise Refusal(f"{path} does not contain valid saved keys") from None
    if len(original) != KEY_BYTES or len(replacement) != KEY_BYTES:
        raise Refusal(f"{path} does not contain 32-byte keys")
    return storage, original, replacement


def _open_database(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise Refusal(f"SQLite database does not exist: {path}")
    if not path.is_file():
        raise Refusal(f"SQLite database path is not a file: {path}")
    return sqlite3.connect(path)


def swap(
    database_url: str,
    username: str,
    *,
    assume_yes: bool,
    state_dir: Path | None = None,
    out: TextIO = sys.stdout,
) -> int:
    _validate_username(username)
    database_path = _database_path(database_url)
    state_path = _state_path(username, state_dir)
    if state_path.exists():
        raise Refusal(
            f"an original key is already saved at {state_path}; run "
            f"`restore {username}` first"
        )

    with closing(_open_database(database_path)) as connection, connection:
        user_id, storage, original = _read_user(connection, username)
        replacement = secrets.token_bytes(KEY_BYTES)

        print(f"Database: {database_path.resolve()}", file=out)
        print(f"User: {username} (id={user_id})", file=out)
        print(f"Storage: {storage}", file=out)
        print(f"Current public key: {_key_text(storage, original)}", file=out)
        print(f"Replacement public key: {_key_text(storage, replacement)}", file=out)
        print(f"Original will be saved to: {state_path}", file=out)

        if not assume_yes:
            print("No changes made. Re-run with --yes to apply.", file=out)
            return 1

        # Save the original before touching the row so a failed update can
        # always be undone with `restore`.
        _write_state(
            state_path,
            username=username,
            database_path=database_path,
            storage=storage,
            original=original,
            replacement=replacement,
        )
        updated = connection.execute(
            "UPDATE users SET public_key = ? WHERE username = ?",
            (_stored_value(storage, replacement), username),
        )
        if updated.rowcount != 1:
            raise Refusal(f"expected to update one row, updated {updated.rowcount}")

    print(f"Updated users.public_key for {username}.", file=out)
    print(f"Original saved to: {state_path}", file=out)
    return 0


def restore(
    database_url: str,
    username: str,
    *,
    assume_yes: bool,
    state_dir: Path | None = None,
    out: TextIO = sys.stdout,
) -> int:
    _validate_username(username)
    database_path = _database_path(database_url)
    state_path = _state_path(username, state_dir)
    if not state_path.exists():
        raise Refusal(
            f"no saved original for {username!r} at {state_path}; run `swap` first"
        )
    storage, original, replacement = _load_state(state_path, username, database_path)

    with closing(_open_database(database_path)) as connection, connection:
        user_id, current_storage, current = _read_user(connection, username)
        if current_storage != storage:
            raise Refusal(
                f"saved original uses {storage} storage but the database now "
                f"stores {current_storage}"
            )

        print(f"Database: {database_path.resolve()}", file=out)
        print(f"User: {username} (id={user_id})", file=out)
        print(f"Storage: {storage}", file=out)
        print(f"Current public key: {_key_text(storage, current)}", file=out)
        print(f"Key to restore: {_key_text(storage, original)}", file=out)
        print(f"Saved original: {state_path}", file=out)

        if current == original:
            state_path.unlink()
            print(f"Already restored; removed {state_path}.", file=out)
            return 0
        if current != replacement:
            raise Refusal(
                "the current public key is neither the swapped key nor the saved "
                "original; refusing to overwrite an unexpected value"
            )

        if not assume_yes:
            print("No changes made. Re-run with --yes to apply.", file=out)
            return 1

        updated = connection.execute(
            "UPDATE users SET public_key = ? WHERE username = ?",
            (_stored_value(storage, original), username),
        )
        if updated.rowcount != 1:
            raise Refusal(f"expected to update one row, updated {updated.rowcount}")

    state_path.unlink()
    print(f"Restored the original public key for {username}.", file=out)
    print(f"Removed saved original: {state_path}", file=out)
    return 0


def _check_environment(settings_obj: Any) -> None:
    if not settings_obj.DEBUG:
        raise Refusal(
            "DEBUG must be True; this script edits a local development database"
        )
    if settings_obj.APP_ENV == "production":
        raise Refusal(
            "APP_ENV must not be production; this script edits a local "
            "development database"
        )


def _load_app_settings() -> Any:
    # `python scripts/simulate_key_swap.py` puts scripts/ on sys.path, not the
    # backend root, so add the root before importing the app package.
    backend_root = Path(__file__).resolve().parents[1]
    if str(backend_root) not in sys.path:
        sys.path.insert(0, str(backend_root))
    from app.core.config import settings

    return settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replace or restore a user's stored public key to simulate a "
            "malicious key-directory server. Development only."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("swap", "replace the stored public key with a random 32-byte key"),
        ("restore", "put the saved original public key back"),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument("username", help="account to change")
        subparser.add_argument(
            "--yes",
            action="store_true",
            help="apply the change; without it the script only prints the plan",
        )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    settings_obj: Any | None = None,
    state_dir: Path | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    output = out if out is not None else sys.stdout
    error = err if err is not None else sys.stderr
    if settings_obj is None:
        settings_obj = _load_app_settings()

    try:
        _check_environment(settings_obj)
        if args.command == "swap":
            return swap(
                settings_obj.DATABASE_URL,
                args.username,
                assume_yes=args.yes,
                state_dir=state_dir,
                out=output,
            )
        return restore(
            settings_obj.DATABASE_URL,
            args.username,
            assume_yes=args.yes,
            state_dir=state_dir,
            out=output,
        )
    except Refusal as exc:
        print(f"Refusing to run: {exc}", file=error)
        return 1
    except (sqlite3.Error, OSError) as exc:
        print(f"Error: {exc}", file=error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
