import uuid
from typing import Dict, List, Any
from core.memory.database import MemoryDatabase

class ExperienceStore:
    def __init__(self, db: MemoryDatabase):
        self.db = db
        
    def record_experience(self, experience: Dict[str, Any]):
        cursor = self.db.get_connection().cursor()
        exp_id = experience.get("experience_id", str(uuid.uuid4()))
        cursor.execute('''
            INSERT OR REPLACE INTO experiences (
                experience_id, test_type, target_fingerprint, endpoint_pattern,
                parameter_type, identity_context, strategy_id, tool, outcome,
                evidence_quality, cost_ms, latency_ms, failure_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            exp_id,
            experience.get("test_type"),
            experience.get("target_fingerprint"),
            experience.get("endpoint_pattern"),
            experience.get("parameter_type"),
            experience.get("identity_context"),
            experience.get("strategy_id"),
            experience.get("tool"),
            experience.get("outcome"),
            experience.get("evidence_quality", 0.0),
            experience.get("cost_ms", 0.0),
            experience.get("latency_ms", 0.0),
            experience.get("failure_reason")
        ))
        self.db.get_connection().commit()
        return exp_id
        
    def retrieve_by_target_fingerprint(self, fingerprint: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        cursor.execute("SELECT * FROM experiences WHERE target_fingerprint = ?", (fingerprint,))
        return [dict(row) for row in cursor.fetchall()]
        
    def retrieve_by_endpoint_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        cursor.execute("SELECT * FROM experiences WHERE endpoint_pattern = ?", (pattern,))
        return [dict(row) for row in cursor.fetchall()]
        
    def retrieve_by_strategy(self, strategy_id: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        cursor.execute("SELECT * FROM experiences WHERE strategy_id = ?", (strategy_id,))
        return [dict(row) for row in cursor.fetchall()]
        
    def retrieve_failed_strategies(self, test_type: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        # Anything not confirmed is basically a failure strategy for that test type
        cursor.execute("SELECT * FROM experiences WHERE test_type = ? AND outcome != 'CONFIRMED'", (test_type,))
        return [dict(row) for row in cursor.fetchall()]
