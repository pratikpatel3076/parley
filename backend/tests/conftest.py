import os
from pathlib import Path

import pytest

TEST_DB = Path(__file__).parent / ".pytest-parley.db"

# Configure the app before any test module imports app.main. Environment
# variables take precedence over .env, so tests never depend on a local file.
os.environ["SECRET_KEY"] = "test-" + "x" * 48
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB.as_posix()}"
os.environ["DEBUG"] = "False"
os.environ["ALLOWED_ORIGINS"] = '["http://localhost:5173"]'


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_database():
    yield
    TEST_DB.unlink(missing_ok=True)
