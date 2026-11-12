import sqlite3
from datetime import datetime

import jwt

from app.core.config import settings
from app.core.security import create_access_token
from support import (
    TEST_DB,
    auth_cookies,
    auth_headers,
    register,
    use_auth,
)


def _claims(access_token: str) -> dict:
    return jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])


def _execute(sql: str, parameters: tuple) -> None:
    connection = sqlite3.connect(TEST_DB)
    try:
        connection.execute(sql, parameters)
        connection.commit()
    finally:
        connection.close()


def _assert_unauthenticated(client) -> None:
    response = client.get("/api/v1/messages/inbox")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Cookie"


def test_access_token_is_rejected_immediately_after_logout(client) -> None:
    register(client)
    access, _ = auth_cookies(client)
    assert client.get("/api/v1/messages/inbox").status_code == 200

    assert client.post(
        "/api/v1/auth/logout", headers=auth_headers()
    ).status_code == 200

    use_auth(client, access, None)
    _assert_unauthenticated(client)


def test_access_token_is_rejected_after_global_revocation(
    client, monkeypatch
) -> None:
    register(client)
    _, refresh = auth_cookies(client)
    rotated = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert rotated.status_code == 200
    access, _ = auth_cookies(client)

    monkeypatch.setattr(settings, "REFRESH_REUSE_GRACE_SECONDS", 0)
    use_auth(client, access, refresh)
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 401
    )

    use_auth(client, access, None)
    _assert_unauthenticated(client)


def test_access_token_is_rejected_after_session_expiry(client) -> None:
    register(client)
    access, _ = auth_cookies(client)
    assert client.get("/api/v1/messages/inbox").status_code == 200

    past = datetime(2000, 1, 1).strftime("%Y-%m-%d %H:%M:%S.%f")
    _execute(
        "UPDATE sessions SET expires_at = ? WHERE id = ?",
        (past, _claims(access)["sid"]),
    )

    use_auth(client, access, None)
    _assert_unauthenticated(client)


def test_access_token_is_rejected_after_user_deletion(client) -> None:
    register(client)
    access, _ = auth_cookies(client)
    assert client.get("/api/v1/messages/inbox").status_code == 200

    _execute("DELETE FROM users WHERE id = ?", (_claims(access)["sub"],))

    use_auth(client, access, None)
    _assert_unauthenticated(client)


def test_session_removal_invalidates_an_otherwise_valid_access_token(
    client,
) -> None:
    register(client)
    access, _ = auth_cookies(client)

    _execute("DELETE FROM sessions WHERE id = ?", (_claims(access)["sid"],))

    use_auth(client, access, None)
    _assert_unauthenticated(client)


def test_a_session_belonging_to_another_user_is_rejected(client) -> None:
    register(client)
    access_a, _ = auth_cookies(client)
    user_a = _claims(access_a)["sub"]

    register(client)
    access_b, _ = auth_cookies(client)
    session_b = _claims(access_b)["sid"]

    # A correctly signed token whose subject does not own the named session.
    forged = create_access_token(user_a, session_b)
    use_auth(client, forged, None)
    _assert_unauthenticated(client)
