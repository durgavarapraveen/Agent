import uuid
from typing import Dict, List, Any

import psycopg2.extras

from core.memory.database import MemoryDatabase, DatabaseManager


class FailureStore:

    def __init__(self, db: MemoryDatabase = None):
        self.db = db

    def record_failure(self, failure: Dict[str, Any]) -> str:
        fail_id = failure.get("failure_id", str(uuid.uuid4()))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO llm_failures (
                        failure_id, provider, model, task, prompt_category,
                        target_fingerprint, failure_type, failure_reason, retry_count
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (failure_id) DO UPDATE SET
                        retry_count = EXCLUDED.retry_count,
                        failure_reason = EXCLUDED.failure_reason
                    """,
                    (
                        fail_id,
                        failure.get("provider", "deepseek"),
                        failure.get("model", "flash"),
                        failure.get("task"),
                        failure.get("prompt_category"),
                        failure.get("target_fingerprint"),
                        failure.get("failure_type"),
                        failure.get("failure_reason"),
                        failure.get("retry_count", 0),
                    ),
                )
                conn.commit()
        return fail_id

    def _fetch(self, sql: str, params: tuple) -> List[Dict[str, Any]]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]

    def get_failures_by_task(self, task: str) -> List[Dict[str, Any]]:
        return self._fetch(
            "SELECT * FROM llm_failures WHERE task = %s ORDER BY created_at DESC LIMIT 500",
            (task,),
        )

    def get_failures_by_fingerprint(self, fingerprint: str) -> List[Dict[str, Any]]:
        return self._fetch(
            "SELECT * FROM llm_failures WHERE target_fingerprint = %s ORDER BY created_at DESC LIMIT 500",
            (fingerprint,),
        )
