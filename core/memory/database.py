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

# --- Added for Sprint 3 (Memory System) ---
import sqlite3

class MemoryDatabase:
    def __init__(self, db_path=".antigravity/memory.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._initialize_schema()
        
    def _initialize_schema(self):
        cursor = self.conn.cursor()
        
        # 1. Experiences Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS experiences (
            experience_id TEXT PRIMARY KEY,
            test_type TEXT,
            target_fingerprint TEXT,
            endpoint_pattern TEXT,
            parameter_type TEXT,
            identity_context TEXT,
            strategy_id TEXT,
            tool TEXT,
            outcome TEXT,
            evidence_quality REAL,
            cost_ms REAL,
            latency_ms REAL,
            failure_reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # 2. Strategies Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS strategies (
            strategy_id TEXT PRIMARY KEY,
            test_type TEXT,
            description TEXT,
            tool TEXT,
            prerequisites TEXT,
            success_rate_global REAL,
            success_rate_target REAL,
            success_rate_type REAL,
            success_rate_recent REAL,
            average_cost_ms REAL,
            average_duration_ms REAL,
            evidence_quality REAL,
            failure_count INTEGER,
            last_used DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # 3. LLM Failures Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS llm_failures (
            failure_id TEXT PRIMARY KEY,
            provider TEXT,
            model TEXT,
            task TEXT,
            prompt_category TEXT,
            target_fingerprint TEXT,
            failure_type TEXT,
            failure_reason TEXT,
            retry_count INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        self.conn.commit()

    def get_connection(self):
        return self.conn
