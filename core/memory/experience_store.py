import uuid
from typing import Dict, List, Any

import psycopg2.extras

from core.memory.database import MemoryDatabase, DatabaseManager


class ExperienceStore:

    def __init__(self, db: MemoryDatabase = None):
        self.db = db

    def record_experience(self, experience: Dict[str, Any]) -> str:
        exp_id = experience.get("experience_id", str(uuid.uuid4()))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO experiences (
                        experience_id, test_type, target_fingerprint, endpoint_pattern,
                        parameter_type, identity_context, strategy_id, tool, outcome,
                        evidence_quality, cost_ms, latency_ms, failure_reason
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (experience_id) DO UPDATE SET
                        outcome = EXCLUDED.outcome,
                        evidence_quality = EXCLUDED.evidence_quality,
                        cost_ms = EXCLUDED.cost_ms,
                        latency_ms = EXCLUDED.latency_ms,
                        failure_reason = EXCLUDED.failure_reason
                    """,
                    (
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
                        experience.get("failure_reason"),
                    ),
                )
                conn.commit()
        return exp_id

    def _fetch(self, sql: str, params: tuple) -> List[Dict[str, Any]]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]

    def retrieve_by_target_fingerprint(self, fingerprint: str) -> List[Dict[str, Any]]:
        return self._fetch(
            "SELECT * FROM experiences WHERE target_fingerprint = %s ORDER BY created_at DESC LIMIT 500",
            (fingerprint,),
        )

    def retrieve_by_endpoint_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        return self._fetch(
            "SELECT * FROM experiences WHERE endpoint_pattern = %s ORDER BY created_at DESC LIMIT 500",
            (pattern,),
        )

    def retrieve_by_strategy(self, strategy_id: str) -> List[Dict[str, Any]]:
        return self._fetch(
            "SELECT * FROM experiences WHERE strategy_id = %s ORDER BY created_at DESC LIMIT 500",
            (strategy_id,),
        )

    def retrieve_failed_strategies(self, test_type: str) -> List[Dict[str, Any]]:
        return self._fetch(
            "SELECT * FROM experiences WHERE test_type = %s AND outcome != 'CONFIRMED' "
            "ORDER BY created_at DESC LIMIT 500",
            (test_type,),
        )
