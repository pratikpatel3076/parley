import os
from pathlib import Path

import pytest

TEST_DB = Path(__file__).parent / ".pytest-parley.db"
TEST_ORIGIN = "https://testserver"

# Configure the app before any test module imports app.main. Environment
# variables take precedence over .env, so tests never depend on a local file.
os.environ["SECRET_KEY"] = "test-" + "x" * 48
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB.as_posix()}"
# The explicit test profile is the only place a reduced bcrypt cost is allowed.
# It keeps the login-path tests from paying the production cost each run.
os.environ["APP_ENV"] = "test"
os.environ["BCRYPT_ROUNDS"] = "4"
os.environ["DEBUG"] = "False"
os.environ["COOKIE_SECURE"] = "True"
os.environ["ALLOWED_ORIGINS"] = '["https://testserver"]'
os.environ["AUTH_RATE_LIMIT_ATTEMPTS"] = "3"
os.environ["AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "60"

from fastapi.testclient import TestClient  # noqa: E402

from app.core.rate_limit import reset_auth_rate_limits  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_database():
    TEST_DB.unlink(missing_ok=True)
    yield
    TEST_DB.unlink(missing_ok=True)


@pytest.fixture
def client():
    with TestClient(app, base_url=TEST_ORIGIN) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_rate_limits():
    reset_auth_rate_limits()
    yield
    reset_auth_rate_limits()
