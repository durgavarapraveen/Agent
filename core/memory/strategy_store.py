import uuid
from typing import Dict, List, Any

import psycopg2.extras

from core.memory.database import MemoryDatabase, DatabaseManager


class StrategyStore:

    def __init__(self, db: MemoryDatabase = None):
        self.db = db

    def record_strategy(self, strategy: Dict[str, Any]) -> str:
        strat_id = strategy.get("strategy_id", str(uuid.uuid4()))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO strategies (
                        strategy_id, test_type, description, tool, prerequisites,
                        success_rate_global, success_rate_target, success_rate_type,
                        success_rate_recent, average_cost_ms, average_duration_ms,
                        evidence_quality, failure_count
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (strategy_id) DO UPDATE SET
                        success_rate_global = EXCLUDED.success_rate_global,
                        success_rate_recent = EXCLUDED.success_rate_recent,
                        failure_count = EXCLUDED.failure_count,
                        last_used = NOW()
                    """,
                    (
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
                        strategy.get("failure_count", 0),
                    ),
                )
                conn.commit()
        return strat_id

    def get_strategies_by_test(self, test_type: str) -> List[Dict[str, Any]]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM strategies WHERE test_type = %s "
                    "ORDER BY success_rate_global DESC LIMIT 500",
                    (test_type,),
                )
                return [dict(r) for r in cur.fetchall()]
