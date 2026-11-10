import base64
import secrets
from pathlib import Path
from uuid import uuid4

TEST_ORIGIN = "https://testserver"
TEST_COOKIE_DOMAIN = "testserver.local"
TEST_DB = Path(__file__).parent / ".pytest-parley.db"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def random_b64(size: int = 32) -> str:
    return b64(secrets.token_bytes(size))


def make_username(prefix: str = "u") -> str:
    return f"{prefix}{uuid4().hex[:12]}"


def auth_headers(origin: str = TEST_ORIGIN) -> dict[str, str]:
    return {"Origin": origin}


def register(
    client,
    *,
    username: str | None = None,
    auth_secret: str | None = None,
    public_key: str | None = None,
    origin: str = TEST_ORIGIN,
):
    username = make_username() if username is None else username
    auth_secret = random_b64(32) if auth_secret is None else auth_secret
    public_key = random_b64(32) if public_key is None else public_key
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "authSecret": auth_secret,
            "publicKey": public_key,
        },
        headers=auth_headers(origin),
    )
    return response, username, auth_secret, public_key


def login(
    client,
    username: str,
    auth_secret: str,
    *,
    origin: str = TEST_ORIGIN,
):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "authSecret": auth_secret},
        headers=auth_headers(origin),
    )


def auth_cookies(client) -> tuple[str, str]:
    return (
        client.cookies.get(
            "parley_access",
            domain=TEST_COOKIE_DOMAIN,
            path="/",
        ),
        client.cookies.get(
            "parley_refresh",
            domain=TEST_COOKIE_DOMAIN,
            path="/api/v1/auth",
        ),
    )


def use_auth(client, access: str, refresh: str | None) -> None:
    client.cookies.clear()
    client.cookies.set(
        "parley_access",
        access,
        domain=TEST_COOKIE_DOMAIN,
        path="/",
    )
    if refresh is not None:
        client.cookies.set(
            "parley_refresh",
            refresh,
            domain=TEST_COOKIE_DOMAIN,
            path="/api/v1/auth",
        )


def message_payload(
    recipient: str,
    *,
    marker: bytes = b"opaque-marker",
    nonce: bytes | None = None,
    client_ts: str = "2026-01-01T00:00:00Z",
) -> dict[str, str]:
    return {
        "recipient": recipient,
        "nonce": b64(nonce if nonce is not None else secrets.token_bytes(24)),
        "ciphertext": b64(marker),
        "client_ts": client_ts,
    }
