import logging
from core.coverage.coverage_engine import CoverageEngine
from core.memory.failure_store import FailureStore
from core.memory.strategy_store import StrategyStore
from typing import Tuple, Optional, Any

logger = logging.getLogger(__name__)

class DecisionGuard:
    def __init__(self, coverage_engine: CoverageEngine, failure_store: FailureStore, strategy_store: StrategyStore = None):
        self.coverage_engine = coverage_engine
        self.failure_store = failure_store
        self.strategy_store = strategy_store
        self.queued_experiments = set()
        
    def validate_experiment(self, experiment: Any) -> Tuple[bool, str, Optional[str]]:
        """
        Validates if an experiment is safe, not duplicate, and not doomed to fail.
        Returns (is_valid, reason, alternative_strategy)
        """
        test_id = getattr(experiment, "test_id", "")
        strategy_id = getattr(experiment, "strategy_id", "default")
        
        # 1. Is exact test already TERMINAL globally?
        if self.coverage_engine.is_test_terminal(test_id):
            return False, "already_tested", None
            
        # 2. Has strategy repeatedly failed?
        failures = self.failure_store.get_failures_by_task(f"{test_id}_{strategy_id}")
        if len(failures) >= 2:
            alt_strategy = "alternative_fallback_strategy"
            if self.strategy_store:
                strats = self.strategy_store.get_strategies_by_test(test_id)
                for s in strats:
                    if s.get("strategy_id") != strategy_id:
                        alt_strategy = s.get("strategy_id")
                        break
            return False, "failed_strategy", alt_strategy
            
        # 3. Are prerequisites satisfied?
        # Assuming prereqs are strings and we check if coverage says they are CONFIRMED or REJECTED (tested)
        prereqs = getattr(experiment, "prerequisites", [])
        for prereq in prereqs:
            if not self.coverage_engine.is_test_terminal(prereq):
                return False, "prerequisite_unmet", None
                
        # 4. Is this duplicate?
        exp_sig = f"{test_id}_{getattr(experiment, 'endpoint_id', '')}_{strategy_id}"
        if exp_sig in self.queued_experiments:
            return False, "duplicate_queued", None
            
        # 5. Is it safe?
        # Simple mock logic
        if getattr(experiment, "is_destructive", False):
            return False, "unsafe_for_mode", None
            
        # Register in queue
        self.queued_experiments.add(exp_sig)
        
        logger.info(f"DECISION_GUARD decision=ACCEPT experiment_id={exp_sig}")
        print(f"DECISION_GUARD decision=ACCEPT experiment_id={exp_sig}")
        
        return True, "accepted", None
