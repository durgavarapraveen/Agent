import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ExperienceStore:
    """Store for past test outcomes and experiences."""

    def __init__(self):
        self.experiences: List[Dict] = []

    def record_experience(self, hypothesis: str, strategy: str, tool: str, outcome: str, 
                          evidence_quality: str, target_fingerprint: str, 
                          endpoint_pattern: str):
        """Add a new detailed experience."""
        experience = {
            "hypothesis": hypothesis,
            "strategy": strategy,
            "tool": tool,
            "outcome": outcome,
            "evidence_quality": evidence_quality,
            "target_fingerprint": target_fingerprint,
            "endpoint_pattern": endpoint_pattern,
            "timestamp": datetime.now().isoformat()
        }
        self.experiences.append(experience)
        logger.info(f"MEMORY_RETRIEVAL: Recorded experience for tool={tool} outcome={outcome}")

    def get_experiences(self) -> List[Dict]:
        """Get all experiences."""
        return self.experiences
