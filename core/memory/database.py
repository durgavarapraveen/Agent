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
        """Ensure pgvector is enabled."""
        with cls.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                conn.commit()

    @classmethod
    @contextmanager
    def get_connection(cls):
        """Context manager for getting a connection from the pool."""
        if cls._pool is None:
            cls.initialize()
            
        conn = cls._pool.getconn()
        try:
            yield conn
        finally:
            cls._pool.putconn(conn)

    @classmethod
    def close_all(cls):
        """Close all connections in the pool."""
        if cls._pool is not None:
            cls._pool.closeall()
            logger.info("Closed all PostgreSQL connections")

# Singleton instance access
db_manager = DatabaseManager()
