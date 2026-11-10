import base64

import pytest

from support import (
    TEST_DB,
    auth_cookies,
    auth_headers,
    b64,
    message_payload,
    register,
    use_auth,
)


def _register(client):
    response, username, auth_secret, public_key = register(client)
    assert response.status_code == 201
    access, refresh = auth_cookies(client)
    assert access and refresh
    return {
        "username": username,
        "auth_secret": auth_secret,
        "public_key": public_key,
        "access": access,
        "refresh": refresh,
    }


def _as(client, user) -> None:
    use_auth(client, user["access"], user["refresh"])


def _send(client, recipient: str, **kwargs):
    return client.post(
        "/api/v1/messages",
        json=message_payload(recipient, **kwargs),
        headers=auth_headers(),
    )


def test_opaque_message_roundtrip_and_isolation(client) -> None:
    alice = _register(client)
    bob = _register(client)

    _as(client, alice)
    marker = b"opaque \x00\x01\xff marker, not base64 or JSON"
    payload = message_payload(bob["username"], marker=marker)
    sent_response = client.post(
        "/api/v1/messages",
        json=payload,
        headers=auth_headers(),
    )

    assert sent_response.status_code == 201
    message_id = sent_response.json()["id"]

    sent = client.get("/api/v1/messages/sent")
    assert sent.status_code == 200
    sent_messages = sent.json()["messages"]
    assert [message["id"] for message in sent_messages] == [message_id]
    assert sent_messages[0]["ciphertext"] == payload["ciphertext"]
    assert base64.b64decode(sent_messages[0]["ciphertext"]) == marker

    # Alice cannot read a message addressed to Bob, even as its sender.
    assert client.get("/api/v1/messages/inbox").json()["messages"] == []

    _as(client, bob)
    inbox = client.get("/api/v1/messages/inbox")
    assert inbox.status_code == 200
    inbox_messages = inbox.json()["messages"]
    assert len(inbox_messages) == 1
    stored = inbox_messages[0]
    assert stored["id"] == message_id
    assert stored["sender"] == alice["username"]
    assert stored["recipient"] == bob["username"]
    assert stored["nonce"] == payload["nonce"]
    assert stored["ciphertext"] == payload["ciphertext"]
    assert base64.b64decode(stored["ciphertext"]) == marker
    assert stored["acked_at"] is None

    # Bob's sent box contains none of Alice's messages.
    assert client.get("/api/v1/messages/sent").json()["messages"] == []


def test_only_the_recipient_can_acknowledge(client) -> None:
    alice = _register(client)
    bob = _register(client)

    _as(client, alice)
    sent_response = _send(client, bob["username"])
    assert sent_response.status_code == 201
    message_id = sent_response.json()["id"]

    sender_ack = client.post(
        f"/api/v1/messages/{message_id}/ack",
        headers=auth_headers(),
    )
    assert sender_ack.status_code == 403

    carol = _register(client)
    _as(client, carol)
    third_party_ack = client.post(
        f"/api/v1/messages/{message_id}/ack",
        headers=auth_headers(),
    )
    assert third_party_ack.status_code == 403

    _as(client, bob)
    first_ack = client.post(
        f"/api/v1/messages/{message_id}/ack",
        headers=auth_headers(),
    )
    assert first_ack.status_code == 200
    assert first_ack.json()["id"] == message_id
    assert first_ack.json()["acked_at"] is not None

    second_ack = client.post(
        f"/api/v1/messages/{message_id}/ack",
        headers=auth_headers(),
    )
    assert second_ack.status_code == 200
    assert second_ack.json()["acked_at"] == first_ack.json()["acked_at"]


def test_ack_unknown_message_returns_404(client) -> None:
    _register(client)

    response = client.post(
        "/api/v1/messages/00000000-0000-4000-8000-000000000000/ack",
        headers=auth_headers(),
    )

    assert response.status_code == 404


def test_ciphertext_size_boundary(client) -> None:
    alice = _register(client)
    bob = _register(client)
    _as(client, alice)

    at_limit = _send(client, bob["username"], marker=b"x" * 65_536)
    assert at_limit.status_code == 201

    too_big = _send(client, bob["username"], marker=b"x" * 65_537)
    assert too_big.status_code == 422
    # The validation error must not echo the rejected body.
    assert "x" * 100 not in too_big.text
    assert len(too_big.text) < 1_000


@pytest.mark.parametrize("nonce_size", [0, 23, 25, 32])
def test_wrong_length_nonce_rejected(client, nonce_size: int) -> None:
    alice = _register(client)
    bob = _register(client)
    _as(client, alice)

    response = _send(client, bob["username"], nonce=b"n" * nonce_size)

    assert response.status_code == 422


def test_invalid_base64_rejected(client) -> None:
    alice = _register(client)
    bob = _register(client)
    _as(client, alice)

    bad_nonce = message_payload(bob["username"])
    bad_nonce["nonce"] = "!!!! not base64 !!!!"
    assert (
        client.post(
            "/api/v1/messages",
            json=bad_nonce,
            headers=auth_headers(),
        ).status_code
        == 422
    )

    bad_ciphertext = message_payload(bob["username"])
    bad_ciphertext["ciphertext"] = "!!!! not base64 !!!!"
    assert (
        client.post(
            "/api/v1/messages",
            json=bad_ciphertext,
            headers=auth_headers(),
        ).status_code
        == 422
    )


def test_recipient_must_exist_and_differ_from_sender(client) -> None:
    alice = _register(client)
    _as(client, alice)

    unknown = _send(client, "missing_user_123")
    assert unknown.status_code == 404

    self_send = _send(client, alice["username"])
    assert self_send.status_code == 400


def test_cursor_pagination_returns_100_per_page(client) -> None:
    alice = _register(client)
    bob = _register(client)
    _as(client, alice)

    for _ in range(101):
        assert _send(client, bob["username"]).status_code == 201

    _as(client, bob)
    first_page = client.get("/api/v1/messages/inbox")
    assert first_page.status_code == 200
    first_body = first_page.json()
    assert len(first_body["messages"]) == 100
    assert first_body["next_cursor"]

    second_page = client.get(
        "/api/v1/messages/inbox",
        params={"after": first_body["next_cursor"]},
    )
    assert second_page.status_code == 200
    second_body = second_page.json()
    assert len(second_body["messages"]) == 1

    all_ids = [message["id"] for message in first_body["messages"]]
    all_ids += [message["id"] for message in second_body["messages"]]
    assert len(set(all_ids)) == 101

    exhausted = client.get(
        "/api/v1/messages/inbox",
        params={"after": second_body["next_cursor"]},
    )
    assert exhausted.status_code == 200
    assert exhausted.json()["messages"] == []
    assert exhausted.json()["next_cursor"] == second_body["next_cursor"]


def test_invalid_cursor_rejected(client) -> None:
    _register(client)

    response = client.get(
        "/api/v1/messages/inbox",
        params={"after": "not-a-cursor"},
    )

    assert response.status_code == 400


def test_database_never_stores_raw_password_or_auth_secret(client) -> None:
    password_marker = "correct-horse-battery-staple-MARKER-9f3a"
    raw_auth_secret = b"auth-secret-marker-0123456789abc"
    assert len(raw_auth_secret) == 32
    auth_secret = b64(raw_auth_secret)

    registered, username, _, _ = register(
        client,
        auth_secret=auth_secret,
    )
    assert registered.status_code == 201
    access, refresh = auth_cookies(client)

    bob = _register(client)
    use_auth(client, access, refresh)
    ciphertext_marker = b"RAW-CIPHERTEXT-MARKER-9f3a"
    sent_response = _send(client, bob["username"], marker=ciphertext_marker)
    assert sent_response.status_code == 201

    database_bytes = TEST_DB.read_bytes()

    # The password never reaches the server at all, and the server only stores
    # a bcrypt hash of the base64 authSecret text, never the text or raw bytes.
    assert password_marker.encode("utf-8") not in database_bytes
    assert auth_secret.encode("ascii") not in database_bytes
    assert raw_auth_secret not in database_bytes
    # The opaque ciphertext itself is stored verbatim.
    assert ciphertext_marker in database_bytes
