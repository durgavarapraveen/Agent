import uuid
from typing import Dict, List, Any
from core.memory.database import MemoryDatabase

class StrategyStore:
    def __init__(self, db: MemoryDatabase):
        self.db = db
        
    def record_strategy(self, strategy: Dict[str, Any]):
        cursor = self.db.get_connection().cursor()
        strat_id = strategy.get("strategy_id", str(uuid.uuid4()))
        cursor.execute('''
            INSERT OR REPLACE INTO strategies (
                strategy_id, test_type, description, tool, prerequisites,
                success_rate_global, success_rate_target, success_rate_type,
                success_rate_recent, average_cost_ms, average_duration_ms,
                evidence_quality, failure_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            strat_id,
            strategy.get("test_type"),
            strategy.get("description"),
            strategy.get("tool"),
            strategy.get("prerequisites", ""),
            strategy.get("success_rate_global", 0.0),
            strategy.get("success_rate_target", 0.0),
            strategy.get("success_rate_type", 0.0),
            strategy.get("success_rate_recent", 0.0),
            strategy.get("average_cost_ms", 0.0),
            strategy.get("average_duration_ms", 0.0),
            strategy.get("evidence_quality", 0.0),
            strategy.get("failure_count", 0)
        ))
        self.db.get_connection().commit()
        return strat_id
        
    def get_strategies_by_test(self, test_type: str) -> List[Dict[str, Any]]:
        cursor = self.db.get_connection().cursor()
        cursor.execute("SELECT * FROM strategies WHERE test_type = ?", (test_type,))
        return [dict(row) for row in cursor.fetchall()]
