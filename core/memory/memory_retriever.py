import logging
from typing import List, Dict

from core.memory.experience_store import ExperienceStore
from core.memory.strategy_store import StrategyStore
from core.memory.failure_store import FailureStore

logger = logging.getLogger(__name__)


class MemoryRetriever:
    """Handles fetching contextually relevant experiences and strategies."""

    def __init__(self, experience_store: ExperienceStore, strategy_store: StrategyStore, failure_store: FailureStore):
        self.experience_store = experience_store
        self.strategy_store = strategy_store
        self.failure_store = failure_store

    def get_relevant_context(self, current_state: Dict) -> Dict:
        """Fetches relevant context for the current state."""
        # A simple placeholder logic for retrieval
        
        target = current_state.get("target")
        
        relevant_experiences = self.experience_store.get_experiences()
        successful_strategies = self.strategy_store.get_successful_strategies()
        failed_tests = self.failure_store.get_failures()

        return {
            "relevant_experiences": relevant_experiences,
            "successful_strategies": successful_strategies,
            "failed_tests": failed_tests
        }
