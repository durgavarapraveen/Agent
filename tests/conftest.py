import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

@pytest.fixture(scope="session", autouse=True)
def _bootstrap_pg_schema():
    """Create the pg_store tables once per test session when Postgres is
    reachable. No-op silently otherwise so unit tests that don't touch the
    DB still work locally without Postgres."""
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

