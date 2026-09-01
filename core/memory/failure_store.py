import logging
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class FailureStore:
    """Store for failed tests and dead-ends to prevent duplicates."""

    def __init__(self):
        self.failures: List[Dict] = []

    def record_failure(self, hypothesis: str, strategy: str, tool: str, failure_reason: str,
                       target_fingerprint: str, endpoint_pattern: str):
        """Log a detailed failure."""
        failure = {
            "hypothesis": hypothesis,
            "strategy": strategy,
            "tool": tool,
            "failure_reason": failure_reason,
            "target_fingerprint": target_fingerprint,
            "endpoint_pattern": endpoint_pattern,
            "timestamp": datetime.now().isoformat()
        }
        self.failures.append(failure)
        logger.info(f"Recorded failure: strategy={strategy} reason={failure_reason}")

    def get_failures(self) -> List[Dict]:
        """Get all failures."""
        return self.failures

    def has_failed_before(self, strategy: str, target_fingerprint: str) -> bool:
        """Check if a specific strategy has failed before on this fingerprint."""
        for failure in self.failures:
            if failure.get("strategy") == strategy and failure.get("target_fingerprint") == target_fingerprint:
                return True
        return False
