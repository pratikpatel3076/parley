from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.config import settings
from support import (
    TEST_COOKIE_DOMAIN,
    auth_cookies,
    auth_headers,
    b64,
    login,
    make_username,
    random_b64,
    register,
    use_auth,
)


def _cookie_headers(response) -> list[str]:
    return response.headers.get_list("set-cookie")


def _find_cookie(headers: list[str], name: str) -> str:
    return next(header for header in headers if header.startswith(f"{name}="))


def test_register_sets_hardened_cookies(client) -> None:
    response, username, _, public_key = register(client)

    assert response.status_code == 201
    payload = response.json()
    assert payload["user"]["username"] == username
    assert payload["user"]["public_key"] == public_key
    assert "auth_hash" not in payload["user"]
    assert "authSecret" not in response.text
    assert "auth_secret" not in response.text

    headers = _cookie_headers(response)
    access = _find_cookie(headers, "parley_access")
    refresh = _find_cookie(headers, "parley_refresh")
    for header in (access, refresh):
        lowered = header.lower()
        assert "httponly" in lowered
        assert "secure" in lowered
        assert "samesite=lax" in lowered
    assert "path=/api/v1/auth" in refresh.lower()


def test_duplicate_username_returns_409(client) -> None:
    first, username, auth_secret, public_key = register(client)
    assert first.status_code == 201

    duplicate = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "authSecret": auth_secret,
            "publicKey": public_key,
        },
        headers=auth_headers(),
    )

    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Username is already taken"}


@pytest.mark.parametrize(
    "username",
    ["Alice", "ab", "a" * 33, "bad-name", "user space", "", "üser"],
)
def test_register_rejects_invalid_usernames(client, username: str) -> None:
    response, *_ = register(client, username=username)

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authSecret", "not base64!!"),
        ("authSecret", b64(b"x" * 31)),
        ("authSecret", b64(b"x" * 33)),
        ("publicKey", "not base64!!"),
        ("publicKey", b64(b"x" * 31)),
        ("publicKey", b64(b"x" * 33)),
    ],
)
def test_register_rejects_bad_base64_and_lengths(
    client, field: str, value: str
) -> None:
    payload = {
        "username": make_username(),
        "authSecret": random_b64(32),
        "publicKey": random_b64(32),
    }
    payload[field] = value

    response = client.post(
        "/api/v1/auth/register",
        json=payload,
        headers=auth_headers(),
    )

    assert response.status_code == 422


def test_validation_errors_do_not_echo_submitted_secrets(client) -> None:
    marker = "AUTHSECRET-ECHO-MARKER"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": make_username(),
            "authSecret": marker,
            "publicKey": random_b64(32),
        },
        headers=auth_headers(),
    )

    assert response.status_code == 422
    assert marker not in response.text
    assert len(response.text) < 1_000


def test_unknown_user_and_wrong_secret_share_login_response(client) -> None:
    registered, username, _, _ = register(client)
    assert registered.status_code == 201

    unknown = login(client, make_username("missing"), random_b64(32))
    wrong_secret = login(client, username, random_b64(32))

    assert unknown.status_code == 401
    assert wrong_secret.status_code == 401
    assert unknown.json() == {"detail": "Invalid credentials"}
    assert wrong_secret.json() == {"detail": "Invalid credentials"}
    assert not unknown.headers.get("set-cookie")
    assert not wrong_secret.headers.get("set-cookie")


def test_login_success_sets_cookies_and_authenticates(client) -> None:
    registered, username, auth_secret, _ = register(client)
    assert registered.status_code == 201
    client.cookies.clear()

    response = login(client, username, auth_secret)

    assert response.status_code == 200
    assert response.json()["user"]["username"] == username
    headers = _cookie_headers(response)
    for name in ("parley_access", "parley_refresh"):
        lowered = _find_cookie(headers, name).lower()
        assert "httponly" in lowered
        assert "secure" in lowered
        assert "samesite=lax" in lowered
    access, refresh = auth_cookies(client)
    assert access
    assert refresh
    assert client.get("/api/v1/messages/inbox").status_code == 200


def test_logout_revokes_session_and_clears_cookies(client) -> None:
    register(client)
    access, refresh = auth_cookies(client)

    response = client.post("/api/v1/auth/logout", headers=auth_headers())

    assert response.status_code == 200
    headers = _cookie_headers(response)
    access_delete = next(
        header
        for header in headers
        if header.startswith('parley_access=""')
    )
    refresh_delete = next(
        header
        for header in headers
        if header.startswith('parley_refresh=""')
    )
    for header in (access_delete, refresh_delete):
        lowered = header.lower()
        assert "max-age=0" in lowered
        assert "httponly" in lowered
        assert "secure" in lowered
        assert "samesite=lax" in lowered

    use_auth(client, access, refresh)
    assert client.get("/api/v1/messages/inbox").status_code == 401
    replay = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert replay.status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/messages/inbox"),
        ("GET", "/api/v1/messages/sent"),
        ("GET", "/api/v1/users/alice/key"),
        ("POST", "/api/v1/messages/00000000-0000-4000-8000-000000000000/ack"),
    ],
)
def test_unauthenticated_requests_return_401(client, method: str, path: str) -> None:
    response = client.request(method, path, headers=auth_headers())

    assert response.status_code == 401
    assert response.status_code != 403


def test_authorization_header_is_not_accepted(client) -> None:
    register(client)
    access, _ = auth_cookies(client)
    client.cookies.clear()

    response = client.get(
        "/api/v1/messages/inbox",
        headers={"Authorization": f"Bearer {access}"},
    )

    assert response.status_code == 401


def test_refresh_rotates_and_old_token_reuse_revokes_sessions(client) -> None:
    register(client)
    access_1, refresh_1 = auth_cookies(client)
    assert access_1 and refresh_1

    first_refresh = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert first_refresh.status_code == 200
    access_2, refresh_2 = auth_cookies(client)
    assert refresh_2 and refresh_2 != refresh_1
    assert access_2 and access_2 != access_1
    assert client.get("/api/v1/messages/inbox").status_code == 200

    # Replay the rotated token. This is treated as theft: every session for the
    # user is revoked, including the replacement created above.
    use_auth(client, access_2, refresh_1)
    replay = client.post("/api/v1/auth/refresh", headers=auth_headers())
    assert replay.status_code == 401

    use_auth(client, access_2, refresh_2)
    assert client.get("/api/v1/messages/inbox").status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 401
    )


def test_refresh_without_cookie_returns_401(client) -> None:
    response = client.post("/api/v1/auth/refresh", headers=auth_headers())

    assert response.status_code == 401


def test_login_rate_limit_triggers(client) -> None:
    registered, username, _, _ = register(client)
    assert registered.status_code == 201

    for _ in range(3):
        assert login(client, username, random_b64(32)).status_code == 401

    limited = login(client, username, random_b64(32))

    assert limited.status_code == 429
    assert limited.headers.get("retry-after") is not None


def test_register_rate_limit_triggers(client) -> None:
    for _ in range(3):
        response, *_ = register(client)
        assert response.status_code == 201

    limited, *_ = register(client)

    assert limited.status_code == 429
    assert limited.headers.get("retry-after") is not None


@pytest.mark.parametrize("origin", ["https://evil.example", None])
def test_disallowed_origin_on_post_returns_403(client, origin: str | None) -> None:
    headers = {} if origin is None else {"Origin": origin}
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": make_username(),
            "authSecret": random_b64(32),
            "publicKey": random_b64(32),
        },
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Origin not allowed"}


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "null",
        "https://testserver.evil.test",
        "https://eviltestserver",
        "http://testserver",
        "https://testserver:8443",
        "https://testserver/",
        "https://testserver:443",
    ],
)
def test_origin_requires_an_exact_allowlist_match(
    client, origin: str | None
) -> None:
    headers = {} if origin is None else {"Origin": origin}
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": make_username(),
            "authSecret": random_b64(32),
            "publicKey": random_b64(32),
        },
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Origin not allowed"}


def test_exact_origin_match_is_accepted(client) -> None:
    response, *_ = register(client, origin="https://testserver")

    assert response.status_code == 201


def test_get_requests_do_not_require_an_origin(client) -> None:
    register(client)
    client.cookies.clear()
    register(client)
    access, refresh = auth_cookies(client)
    use_auth(client, access, refresh)

    response = client.get("/api/v1/messages/inbox")

    assert response.status_code == 200
    assert "origin" not in {key.lower() for key in response.request.headers}


def test_logout_without_cookies_succeeds_and_clears_both(client) -> None:
    response = client.post("/api/v1/auth/logout", headers=auth_headers())

    assert response.status_code == 200
    headers = _cookie_headers(response)
    assert any(header.startswith('parley_access=""') for header in headers)
    assert any(header.startswith('parley_refresh=""') for header in headers)


def test_logout_with_only_a_refresh_cookie_revokes_the_session(client) -> None:
    register(client)
    access, refresh = auth_cookies(client)
    assert access and refresh

    client.cookies.clear()
    client.cookies.set(
        "parley_refresh",
        refresh,
        domain=TEST_COOKIE_DOMAIN,
        path="/api/v1/auth",
    )

    response = client.post("/api/v1/auth/logout", headers=auth_headers())
    assert response.status_code == 200

    use_auth(client, access, refresh)
    assert client.get("/api/v1/messages/inbox").status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 401
    )


def test_logout_with_expired_access_and_valid_refresh_revokes_it(client) -> None:
    register(client)
    access, refresh = auth_cookies(client)
    assert access and refresh

    payload = jwt.decode(
        access,
        settings.SECRET_KEY,
        algorithms=["HS256"],
    )
    payload["exp"] = datetime.now(timezone.utc) - timedelta(seconds=5)
    expired_access = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    use_auth(client, expired_access, refresh)
    response = client.post("/api/v1/auth/logout", headers=auth_headers())
    assert response.status_code == 200

    use_auth(client, access, refresh)
    assert client.get("/api/v1/messages/inbox").status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", headers=auth_headers()).status_code
        == 401
    )


def test_origin_is_still_required_for_logout(client) -> None:
    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 403


def _cookie_attributes(header: str) -> dict[str, str]:
    _, _, attributes = header.partition(";")
    result: dict[str, str] = {}
    for attribute in attributes.split(";"):
        attribute = attribute.strip()
        if not attribute:
            continue
        key, _, value = attribute.partition("=")
        result[key.lower()] = value.lower()
    return result


def test_cookie_delete_attributes_match_set_attributes(client) -> None:
    registered, *_ = register(client)
    set_headers = _cookie_headers(registered)

    logged_out = client.post("/api/v1/auth/logout", headers=auth_headers())
    delete_headers = _cookie_headers(logged_out)

    for name in ("parley_access", "parley_refresh"):
        set_attributes = _cookie_attributes(_find_cookie(set_headers, name))
        delete_attributes = _cookie_attributes(
            _find_cookie(delete_headers, name)
        )
        for attribute in (
            "path",
            "domain",
            "secure",
            "httponly",
            "samesite",
        ):
            assert set_attributes.get(attribute, "") == delete_attributes.get(
                attribute, ""
            ), f"{name} {attribute} differs between set and delete"


def test_origin_check_covers_non_auth_state_changes(client) -> None:
    register(client)
    access, refresh = auth_cookies(client)
    assert access and refresh
    assert client.get("/api/v1/messages/inbox").status_code == 200

    # The Origin check runs before routing, so an otherwise valid session still
    # cannot perform a state-changing request from a disallowed origin.
    response = client.post(
        "/api/v1/messages/00000000-0000-4000-8000-000000000000/ack",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403
