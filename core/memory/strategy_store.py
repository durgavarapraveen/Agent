import logging
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class StrategyStore:
    """Store for pentest strategies."""

    def __init__(self):
        self.strategies: List[Dict] = []

    def record_strategy(self, hypothesis: str, strategy: str, tool: str, outcome: str, 
                        evidence_quality: str, target_fingerprint: str, endpoint_pattern: str):
        """Add a detailed strategy execution record."""
        strategy_record = {
            "hypothesis": hypothesis,
            "strategy": strategy,
            "tool": tool,
            "outcome": outcome,
            "evidence_quality": evidence_quality,
            "target_fingerprint": target_fingerprint,
            "endpoint_pattern": endpoint_pattern,
            "timestamp": datetime.now().isoformat()
        }
        self.strategies.append(strategy_record)
        logger.info(f"STRATEGY_SELECTED: strategy={strategy} for tool={tool}")

    def get_successful_strategies(self) -> List[Dict]:
        return [s for s in self.strategies if s.get("outcome") == "success"]

    def get_failed_strategies(self) -> List[Dict]:
        return [s for s in self.strategies if s.get("outcome") == "failure"]
