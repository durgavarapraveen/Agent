from core.memory.experience_store import ExperienceStore
from core.memory.strategy_store import StrategyStore
from core.memory.failure_store import FailureStore
import logging

logger = logging.getLogger(__name__)

class MemoryRetriever:
    def __init__(self, exp_store: ExperienceStore, strat_store: StrategyStore, fail_store: FailureStore):
        self.exp_store = exp_store
        self.strat_store = strat_store
        self.fail_store = fail_store
        
    def retrieve_relevant_experiences(self, endpoint_id: str, test_type: str) -> list:
        # In a real impl, we'd do vector similarity or more complex joins.
        # For now, we'll fetch experiences for this test type.
        # Assuming we can mock endpoint matching for now.
        experiences = self.exp_store.retrieve_failed_strategies(test_type)
        return experiences
        
    def retrieve_successful_strategies(self, test_type: str) -> list:
        strategies = self.strat_store.get_strategies_by_test(test_type)
        # Filter for high global/target success rates
        return [s for s in strategies if s.get("success_rate_global", 0) > 0.5]
        
    def retrieve_failed_strategies(self, test_type: str) -> list:
        return self.exp_store.retrieve_failed_strategies(test_type)
        
    def log_retrieval_stats(self, experiences, avoided):
        logger.info(f"MEMORY_RETRIEVAL similar_experiences={len(experiences)} failed_strategies_avoided={len(avoided)}")
        print(f"MEMORY_RETRIEVAL similar_experiences={len(experiences)} failed_strategies_avoided={len(avoided)}")
