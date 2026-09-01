import sqlite3
import os
import logging

logger = logging.getLogger(__name__)

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
