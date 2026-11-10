from support import auth_headers, make_username, register


def test_key_directory_returns_public_key_for_known_user(client) -> None:
    _, bob, _, bob_key = register(client)
    register(client)

    response = client.get(f"/api/v1/users/{bob}/key", headers=auth_headers())

    assert response.status_code == 200
    assert response.json() == {"username": bob, "public_key": bob_key}


def test_key_directory_returns_404_for_unknown_user(client) -> None:
    register(client)

    response = client.get(
        f"/api/v1/users/{make_username('missing')}/key",
        headers=auth_headers(),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}


def test_key_directory_returns_404_for_invalid_username(client) -> None:
    register(client)

    response = client.get("/api/v1/users/Not-A-User/key", headers=auth_headers())

    assert response.status_code == 404


def test_key_directory_requires_authentication(client) -> None:
    _, bob, _, _ = register(client)
    client.cookies.clear()

    response = client.get(f"/api/v1/users/{bob}/key", headers=auth_headers())

    assert response.status_code == 401


def test_key_directory_does_not_expose_private_material(client) -> None:
    _, bob, _, _ = register(client)
    register(client)

    response = client.get(f"/api/v1/users/{bob}/key", headers=auth_headers())

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"username", "public_key"}
    assert len(body["public_key"]) == 44
    assert "auth" not in body
    assert "secret" not in response.text.lower()
