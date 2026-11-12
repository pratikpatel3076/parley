import asyncio
import sqlite3
from datetime import datetime
from uuid import uuid4

import jwt

from app.core.config import settings
from app.db.database import engine, init_db
from app.main import app
from support import (
    TEST_COOKIE_DOMAIN,
    TEST_DB,
    TEST_ORIGIN,
    auth_cookies,
    auth_headers,
    login,
    random_b64,
    register,
    use_auth,
)

from httpx2 import ASGITransport, AsyncClient


def _delete_headers(response) -> dict[str, bool]:
    headers = response.headers.get_list("set-cookie")
    return {
        "access": any(
            header.startswith('parley_access=""') for header in headers
        ),
        "refresh": any(
            header.startswith('parley_refresh=""') for header in headers
        ),
    }


def _claims(access_token: str) -> dict:
    return jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])


def _session_rows(user_id: str) -> list[sqlite3.Row]:
    connection = sqlite3.connect(TEST_DB)
    connection.row_factory = sqlite3.Row
    try:
        return list(
            connection.execute(
                "SELECT * FROM sessions WHERE user_id = ?", (user_id,)
            ).fetchall()
        )
    finally:
        connection.close()


def _expire_session(session_id: str) -> None:
    past = (datetime(2000, 1, 1)).strftime("%Y-%m-%d %H:%M:%S.%f")
    connection = sqlite3.connect(TEST_DB)
    try:
        connection.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (past, session_id),
        )
        connection.commit()
    finally:
        connection.close()


def _second_session(client, username: str, auth_secret: str):
    response = login(client, username, auth_secret)
    assert response.status_code == 200
    return auth_cookies(client)


def test_logout_then_old_refresh_replay_leaves_other_session_alive(
    client,
) -> None:
    registered, username, auth_secret, _ = register(client)
    assert registered.status_code == 201
    access_a, refresh_a = auth_cookies(client)

    client.cookies.clear()
    access_b, refresh_b = _second_session(client, username, auth_secret)
    assert refresh_b != refresh_a
    user_id = _claims(access_a)["sub"]

    logout = client.post("/api/v1/auth/logout", headers=auth_headers())
    assert logout.status_code == 200

    use_auth(client, access_b, refresh_b)
    replay = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert replay.status_code == 401
    assert _delete_headers(replay) == {"access": True, "refresh": True}

    rows = {row["id"]: row for row in _session_rows(user_id)}
    assert rows[_claims(access_b)["sid"]]["revoked_reason"] == "logout"
    surviving = rows[_claims(access_a)["sid"]]
    assert surviving["revoked"] == 0
    assert surviving["revoked_reason"] is None

    # The other session is untouched: it still authenticates and refreshes.
    use_auth(client, access_a, refresh_a)
    assert client.get("/api/v1/messages/inbox").status_code == 200
    refreshed = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert refreshed.status_code == 200


def test_rotated_replay_after_grace_revokes_every_live_session(
    client, monkeypatch
) -> None:
    registered, username, auth_secret, _ = register(client)
    assert registered.status_code == 201
    access_a, refresh_a = auth_cookies(client)
    user_id = _claims(access_a)["sub"]

    client.cookies.clear()
    access_b, refresh_b = _second_session(client, username, auth_secret)

    use_auth(client, access_b, refresh_b)
    rotated = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert rotated.status_code == 200
    access_b2, refresh_b2 = auth_cookies(client)

    monkeypatch.setattr(settings, "REFRESH_REUSE_GRACE_SECONDS", 0)
    use_auth(client, access_b2, refresh_b)
    replay = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert replay.status_code == 401
    assert _delete_headers(replay) == {"access": True, "refresh": True}

    rows = _session_rows(user_id)
    assert rows
    assert all(row["revoked"] for row in rows)
    reasons = {row["id"]: row["revoked_reason"] for row in rows}
    assert reasons[_claims(access_b2)["sid"]] == "reuse_detected"
    assert reasons[_claims(access_a)["sid"]] == "reuse_detected"

    # The replacement cannot be used, and no access token from this user works.
    use_auth(client, access_b2, refresh_b2)
    assert client.get("/api/v1/messages/inbox").status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 401
    )
    use_auth(client, access_a, refresh_a)
    assert client.get("/api/v1/messages/inbox").status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 401
    )


def test_rotated_replay_within_grace_keeps_the_replacement(client) -> None:
    register(client)
    access_1, refresh_1 = auth_cookies(client)

    rotated = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert rotated.status_code == 200
    access_2, refresh_2 = auth_cookies(client)
    assert refresh_2 != refresh_1

    use_auth(client, access_2, refresh_1)
    replay = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert replay.status_code == 401
    # A concurrent tab may already hold the new cookies: do not delete them.
    assert replay.headers.get_list("set-cookie") == []

    use_auth(client, access_2, refresh_2)
    assert client.get("/api/v1/messages/inbox").status_code == 200
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 200
    )


def test_expired_refresh_does_not_revoke_other_sessions(client) -> None:
    registered, username, auth_secret, _ = register(client)
    assert registered.status_code == 201
    access_a, refresh_a = auth_cookies(client)

    client.cookies.clear()
    access_b, refresh_b = _second_session(client, username, auth_secret)
    user_id = _claims(access_a)["sub"]
    _expire_session(_claims(access_b)["sid"])

    use_auth(client, access_b, refresh_b)
    replay = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert replay.status_code == 401
    assert _delete_headers(replay) == {"access": True, "refresh": True}

    use_auth(client, access_a, refresh_a)
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 200
    )

    rows = {row["id"]: row for row in _session_rows(user_id)}
    assert rows[_claims(access_b)["sid"]]["revoked_reason"] == "expired"


def test_refresh_401_paths_clear_cookies(client) -> None:
    client.cookies.clear()
    missing = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert missing.status_code == 401
    assert _delete_headers(missing) == {"access": True, "refresh": True}

    client.cookies.clear()
    client.cookies.set(
        "parley_refresh",
        "not-a-real-refresh-token",
        domain=TEST_COOKIE_DOMAIN,
        path="/api/v1/auth",
    )
    unknown = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert unknown.status_code == 401
    assert _delete_headers(unknown) == {"access": True, "refresh": True}


async def test_concurrent_refresh_rotates_exactly_once() -> None:
    await init_db()
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(
            transport=transport, base_url=TEST_ORIGIN
        ) as setup:
            registered = await setup.post(
                "/api/v1/auth/register",
                json={
                    "username": f"race{uuid4().hex[:12]}",
                    "authSecret": random_b64(32),
                    "publicKey": random_b64(32),
                },
                headers={"Origin": TEST_ORIGIN},
            )
        assert registered.status_code == 201
        refresh = registered.cookies.get("parley_refresh")
        assert refresh

        cookie_header = {
            "Origin": TEST_ORIGIN,
            "Cookie": f"parley_refresh={refresh}",
        }
        async with (
            AsyncClient(transport=transport, base_url=TEST_ORIGIN) as first,
            AsyncClient(transport=transport, base_url=TEST_ORIGIN) as second,
        ):
            results = await asyncio.gather(
                first.post("/api/v1/auth/refresh", headers=cookie_header),
                second.post("/api/v1/auth/refresh", headers=cookie_header),
            )

        assert sorted(result.status_code for result in results) == [200, 401]
        winner = next(
            result for result in results if result.status_code == 200
        )
        replacement = winner.cookies.get("parley_refresh")
        assert replacement and replacement != refresh

        # The loser must not have triggered a global logout: the replacement
        # still rotates.
        async with AsyncClient(
            transport=transport, base_url=TEST_ORIGIN
        ) as follow_up:
            rotated_again = await follow_up.post(
                "/api/v1/auth/refresh",
                headers={
                    "Origin": TEST_ORIGIN,
                    "Cookie": f"parley_refresh={replacement}",
                },
            )
        assert rotated_again.status_code == 200
    finally:
        await engine.dispose()
