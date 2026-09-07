"""Smoke test: pg_store schema migrates cleanly against Postgres.

Skipped when Postgres is not reachable (dev laptops without docker).
CI provides Postgres via services: block in .github/workflows/ci.yml.
"""
from __future__ import annotations

import os

import pytest


def _pg_reachable() -> bool:
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


pytestmark = pytest.mark.skipif(not _pg_reachable(),
                                 reason="Postgres not reachable — dev machine without docker")


def test_pg_init_schema_idempotent() -> None:
    """_init_schema must be safe to call twice; second call is a no-op."""
    from core.database.pg_store import _init_schema
    _init_schema()
    _init_schema()


def test_required_tables_exist() -> None:
    from core.memory.database import DatabaseManager
    from core.database.pg_store import _init_schema
    _init_schema()

    required = {
        "targets", "scans", "vulnerabilities", "findings_dedup",
        "findings_history", "tool_output", "audit_log",
    }
    with DatabaseManager.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT tablename FROM pg_tables
                WHERE schemaname = current_schema()
            """)
            present = {row[0] for row in cur.fetchall()}

    missing = required - present
    assert not missing, f"schema is missing tables: {sorted(missing)}"
