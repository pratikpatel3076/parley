import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

BCRYPT_ROUNDS = 12

# A fixed-format input hashed at import time. Login uses it when the username is
# unknown so that path performs the same bcrypt work as a real wrong secret.
_DUMMY_AUTH_TEXT = base64.b64encode(b"\x00" * 32).decode("ascii")
_DUMMY_AUTH_HASH = bcrypt.hashpw(
    _DUMMY_AUTH_TEXT.encode("ascii"),
    bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
).decode("ascii")


def utcnow() -> datetime:
    """Return naive UTC for SQLite storage and comparisons."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_auth_secret(auth_secret_b64: str) -> str:
    """Hash the base64 text (44 ASCII characters), never the decoded bytes."""
    encoded = auth_secret_b64.encode("ascii")
    return bcrypt.hashpw(
        encoded,
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("ascii")


def verify_auth_secret(auth_secret_b64: str, auth_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            auth_secret_b64.encode("ascii"),
            auth_hash.encode("ascii"),
        )
    except (ValueError, TypeError):
        return False


def dummy_auth_hash() -> str:
    return _DUMMY_AUTH_HASH


def create_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def create_access_token(user_id: str, session_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": user_id,
        "sid": session_id,
        "typ": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "iat", "sub", "sid", "typ"]},
        )
    except jwt.InvalidTokenError:
        return None
    if payload.get("typ") != "access":
        return None
    if not isinstance(payload.get("sub"), str) or not isinstance(
        payload.get("sid"), str
    ):
        return None
    return payload
