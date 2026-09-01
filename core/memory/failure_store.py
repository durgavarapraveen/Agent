import uuid
from typing import Dict, List, Any
from core.memory.database import MemoryDatabase

class FailureStore:
    def __init__(self, db: MemoryDatabase):
        self.db = db
        
    def record_failure(self, failure: Dict[str, Any]):
        cursor = self.db.get_connection().cursor()
        fail_id = failure.get("failure_id", str(uuid.uuid4()))
        cursor.execute('''
            INSERT INTO llm_failures (
                failure_id, provider, model, task, prompt_category,
                target_fingerprint, failure_type, failure_reason, retry_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            fail_id,
            failure.get("provider", "deepseek"),
            failure.get("model", "flash"),
            failure.get("task"),
            failure.get("prompt_category"),
            failure.get("target_fingerprint"),
            failure.get("failure_type"),
            failure.get("failure_reason"),
            failure.get("retry_count", 0)
        ))
        self.db.get_connection().commit()
        return fail_id
        
    def get_failures_by_task(self, task: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        cursor.execute("SELECT * FROM llm_failures WHERE task = ?", (task,))
        return [dict(row) for row in cursor.fetchall()]
        
    def get_failures_by_fingerprint(self, fingerprint: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        cursor.execute("SELECT * FROM llm_failures WHERE target_fingerprint = ?", (fingerprint,))
        return [dict(row) for row in cursor.fetchall()]
