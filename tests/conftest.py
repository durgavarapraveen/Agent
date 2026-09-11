import base64
import os
import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ---------------------------------------------------------------------------
# Encryption key for the test session.
#
# Signing/verification code (core.security.execution_contract, encryption.py)
# requires a real key. Production and CI supply ENCRYPTION_KEY via env; provide
# a deterministic 32-byte test key here so unit tests that exercise signing do
# not depend on ambient environment. `setdefault` means a real key already in
# the environment (CI) always wins.
# ---------------------------------------------------------------------------
os.environ.setdefault(
    "ENCRYPTION_KEY", base64.b64encode(bytes(range(32))).decode("ascii")
)


def _pg_reachable() -> bool:
    """True if a Postgres server is reachable with the configured credentials.

    Used to auto-skip @pytest.mark.integration tests on dev machines / CI runs
    without a database. Mirrors the guard already used in test_db_schema.py and
    test_rag_roundtrip.py.
    """
    try:
        import psycopg2

        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            user=os.getenv("POSTGRES_USER", "ci_user"),
            password=os.getenv("POSTGRES_PASSWORD", "ci_pw"),
            dbname=os.getenv("POSTGRES_DB", "ci_db"),
            connect_timeout=2,
        )
        conn.close()
        return True
    except Exception:
        return False


# Evaluate once per session.
_PG_REACHABLE = _pg_reachable()


def pytest_collection_modifyitems(config, items):
    """Skip integration tests (which exercise Postgres / external services) when
    no database is reachable, so the default `pytest tests/` run is green on a
    machine without Postgres. When a DB is present (CI), they run normally.
    """
    if _PG_REACHABLE:
        return
    skip_integration = pytest.mark.skip(
        reason="Postgres not reachable — integration test skipped (start Postgres to run)"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(scope="session", autouse=True)
def _bootstrap_pg_schema():
    try:
        from core.database.pg_store import _init_schema
        _init_schema()
    except Exception:
        pass
    yield


@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture
def event_loop():
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
