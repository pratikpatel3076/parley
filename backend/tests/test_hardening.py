import logging
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.config import settings
from support import (
    auth_cookies,
    auth_headers,
    b64,
    message_payload,
    random_b64,
    register,
    use_auth,
)


def _valid_token_payload(client) -> dict:
    register(client)
    access, refresh = auth_cookies(client)
    assert access and refresh
    return jwt.decode(access, settings.SECRET_KEY, algorithms=["HS256"])


def _assert_security_headers(response) -> None:
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("algorithm", ["none", "HS384", "HS512"])
def test_access_token_algorithm_is_pinned_to_hs256(
    client, algorithm: str
) -> None:
    payload = _valid_token_payload(client)
    # A long dummy key avoids the library's key-length warning for HS512; the
    # point of the test is that decoding only accepts the pinned HS256.
    key = None if algorithm == "none" else settings.SECRET_KEY + "x" * 32
    token = jwt.encode(payload, key, algorithm=algorithm)

    use_auth(client, token, None)
    assert client.get("/api/v1/messages/inbox").status_code == 401


@pytest.mark.parametrize("claim", ["exp", "sub", "iat", "sid", "typ"])
def test_required_access_token_claims(client, claim: str) -> None:
    payload = _valid_token_payload(client)
    del payload[claim]
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    use_auth(client, token, None)
    assert client.get("/api/v1/messages/inbox").status_code == 401


def test_access_token_type_claim_is_enforced(client) -> None:
    payload = _valid_token_payload(client)
    payload["typ"] = "refresh"
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    use_auth(client, token, None)
    assert client.get("/api/v1/messages/inbox").status_code == 401


def test_expired_access_token_is_rejected(client) -> None:
    payload = _valid_token_payload(client)
    payload["exp"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    use_auth(client, token, None)
    assert client.get("/api/v1/messages/inbox").status_code == 401


def test_refresh_token_cannot_be_used_as_access(client) -> None:
    register(client)
    _, refresh = auth_cookies(client)
    assert refresh

    use_auth(client, refresh, None)
    assert client.get("/api/v1/messages/inbox").status_code == 401


def test_access_token_cannot_be_used_as_refresh(client) -> None:
    register(client)
    access, _ = auth_cookies(client)
    assert access

    use_auth(client, access, access)
    response = client.post("/api/v1/auth/refresh", headers=auth_headers())

    assert response.status_code == 401


def test_auth_and_message_responses_are_not_cacheable(client) -> None:
    registered, *_ = register(client)
    assert registered.status_code == 201
    _assert_security_headers(registered)

    inbox = client.get("/api/v1/messages/inbox")
    assert inbox.status_code == 200
    _assert_security_headers(inbox)

    client.cookies.clear()
    unauthenticated = client.get("/api/v1/messages/inbox")
    assert unauthenticated.status_code == 401
    _assert_security_headers(unauthenticated)

    rejected_origin = client.post("/api/v1/auth/logout")
    assert rejected_origin.status_code == 403
    _assert_security_headers(rejected_origin)


def test_rate_limiter_uses_direct_ip_and_ignores_x_forwarded_for(
    client,
) -> None:
    registered, username, _, _ = register(client)
    assert registered.status_code == 201

    for index in range(3):
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": username,
                "authSecret": random_b64(32),
            },
            headers={
                **auth_headers(),
                "X-Forwarded-For": f"203.0.113.{index + 1}",
            },
        )
        assert response.status_code == 401

    limited = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "authSecret": random_b64(32),
        },
        headers={
            **auth_headers(),
            "X-Forwarded-For": "198.51.100.9",
        },
    )

    assert limited.status_code == 429


def test_secrets_bodies_and_auth_headers_are_not_logged(client, caplog) -> None:
    caplog.set_level(logging.DEBUG)

    auth_secret = b64(b"log-marker-" + b"x" * 21)
    ciphertext_marker = b"LOGGING-CIPHERTEXT-MARKER-9f3a"
    body_marker = "LOGGING-BODY-MARKER-9f3a"
    authorization_marker = "LOGGING-AUTHORIZATION-MARKER-9f3a"
    password_marker = "LOGGING-PASSWORD-MARKER-9f3a"

    registered, _, _, _ = register(client, auth_secret=auth_secret)
    assert registered.status_code == 201
    alice_access, alice_refresh = auth_cookies(client)

    bob_response, bob, _, _ = register(client)
    assert bob_response.status_code == 201

    use_auth(client, alice_access, alice_refresh)
    payload = message_payload(bob, marker=ciphertext_marker)
    sent = client.post(
        "/api/v1/messages",
        json=payload,
        headers={
            **auth_headers(),
            "Authorization": f"Bearer {authorization_marker}",
            "X-Password": password_marker,
        },
    )
    assert sent.status_code == 201

    combined_logs = caplog.text
    assert auth_secret not in combined_logs
    assert payload["ciphertext"] not in combined_logs
    assert ciphertext_marker.decode("ascii") not in combined_logs
    assert body_marker not in combined_logs
    assert authorization_marker not in combined_logs
    assert password_marker not in combined_logs
