import os
import logging
from contextlib import contextmanager
from psycopg2 import pool
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

DB_HOST = os.getenv("POSTGRES_HOST", os.getenv("DB_HOST", "localhost"))
DB_PORT = os.getenv("POSTGRES_PORT", os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB", os.getenv("DB_NAME", "pentesting_db"))
DB_USER = os.getenv("POSTGRES_USER", os.getenv("DB_USER", "pentesting_user"))
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", os.getenv("DB_PASSWORD", "pentesting_password"))
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "5"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "20"))

class DatabaseManager:
    _pool = None

    @classmethod
    def initialize(cls):
        if cls._pool is None:
            try:
                cls._pool = pool.ThreadedConnectionPool(
                    DB_POOL_MIN,
                    DB_POOL_MAX,
                    host=DB_HOST,
                    port=DB_PORT,
                    dbname=DB_NAME,
                    user=DB_USER,
                    password=DB_PASSWORD
                )
                logger.info(f"Initialized PostgreSQL connection pool (min={DB_POOL_MIN}, max={DB_POOL_MAX})")
                cls._init_extensions()
            except Exception as e:
                logger.error(f"Failed to initialize PostgreSQL pool: {e}")
                raise

    @classmethod
    def _init_extensions(cls):
        try:
            with cls.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                    conn.commit()
        except Exception as e:
            try:
                # roll back the aborted transaction so the connection is reusable
                conn.rollback()
            except Exception:
                pass
            logger.warning(f"pgvector extension not enabled (vector memory disabled, core DB unaffected): {e}")

    @classmethod
    @contextmanager
    def get_connection(cls):
        if cls._pool is None:
            cls.initialize()

        conn = cls._pool.getconn()
        broken = False
        try:
            yield conn
        except Exception:
            try:
                conn.rollback()
            except Exception:
                broken = True
            raise
        finally:
            # Best-effort rollback on happy path so we never return a conn with an
            # implicit open transaction.
            if not broken:
                try:
                    conn.rollback()
                except Exception:
                    broken = True
            try:
                cls._pool.putconn(conn, close=broken)
            except Exception as e:
                logger.error(f"Failed to return connection to pool (dropping): {e}")

    @classmethod
    def close_all(cls):
        if cls._pool is not None:
            cls._pool.closeall()
            logger.info("Closed all PostgreSQL connections")

# Singleton instance access
db_manager = DatabaseManager()


class MemoryDatabase:

    def __init__(self, db_path=None):
        self._ensure_schema()

    def _ensure_schema(self):
        try:
            from core.database.pg_store import _init_schema
            _init_schema()
        except Exception:
            pass

    def get_connection(self):
        return DatabaseManager.get_connection()

    def record_experience(self, experience_id, test_type="", target_fingerprint="",
                          endpoint_pattern="", parameter_type="", identity_context="",
                          strategy_id="", tool="", outcome="", evidence_quality=0.0,
                          cost_ms=0.0, latency_ms=0.0, failure_reason=""):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO experiences
                    (experience_id, test_type, target_fingerprint, endpoint_pattern,
                     parameter_type, identity_context, strategy_id, tool, outcome,
                     evidence_quality, cost_ms, latency_ms, failure_reason)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (experience_id) DO UPDATE SET
                        outcome=EXCLUDED.outcome, evidence_quality=EXCLUDED.evidence_quality
                """, (experience_id, test_type, target_fingerprint, endpoint_pattern,
                      parameter_type, identity_context, strategy_id, tool, outcome,
                      evidence_quality, cost_ms, latency_ms, failure_reason))
                conn.commit()

    def record_strategy(self, strategy_id, test_type="", description="", tool="",
                        prerequisites="", success_rate_global=0.0, success_rate_target=0.0,
                        success_rate_type=0.0, success_rate_recent=0.0, average_cost_ms=0.0,
                        average_duration_ms=0.0, evidence_quality=0.0, failure_count=0):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO strategies
                    (strategy_id, test_type, description, tool, prerequisites,
                     success_rate_global, success_rate_target, success_rate_type,
                     success_rate_recent, average_cost_ms, average_duration_ms,
                     evidence_quality, failure_count)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (strategy_id) DO UPDATE SET
                        success_rate_global=EXCLUDED.success_rate_global,
                        success_rate_recent=EXCLUDED.success_rate_recent,
                        failure_count=EXCLUDED.failure_count, last_used=NOW()
                """, (strategy_id, test_type, description, tool, prerequisites,
                      success_rate_global, success_rate_target, success_rate_type,
                      success_rate_recent, average_cost_ms, average_duration_ms,
                      evidence_quality, failure_count))
                conn.commit()

    def record_llm_failure(self, failure_id, provider="", model="", task="",
                           prompt_category="", target_fingerprint="",
                           failure_type="", failure_reason="", retry_count=0):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO llm_failures
                    (failure_id, provider, model, task, prompt_category,
                     target_fingerprint, failure_type, failure_reason, retry_count)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (failure_id) DO UPDATE SET
                        retry_count=EXCLUDED.retry_count, failure_reason=EXCLUDED.failure_reason
                """, (failure_id, provider, model, task, prompt_category,
                      target_fingerprint, failure_type, failure_reason, retry_count))
                conn.commit()

    def get_experiences(self, test_type: str = "", limit: int = 100):
        with DatabaseManager.get_connection() as conn:
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if test_type:
                    cur.execute("SELECT * FROM experiences WHERE test_type=%s ORDER BY created_at DESC LIMIT %s",
                                (test_type, limit))
                else:
                    cur.execute("SELECT * FROM experiences ORDER BY created_at DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]

    def get_strategies(self, test_type: str = "", limit: int = 50):
        with DatabaseManager.get_connection() as conn:
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if test_type:
                    cur.execute("SELECT * FROM strategies WHERE test_type=%s ORDER BY success_rate_global DESC LIMIT %s",
                                (test_type, limit))
                else:
                    cur.execute("SELECT * FROM strategies ORDER BY success_rate_global DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]

    def get_llm_failures(self, limit: int = 100):
        with DatabaseManager.get_connection() as conn:
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM llm_failures ORDER BY created_at DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]
