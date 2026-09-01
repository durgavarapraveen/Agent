import logging
from core.coverage.coverage_state import CoverageStateStore
from core.coverage.test_definition import TestState

logger = logging.getLogger(__name__)


class ConvergenceEngine:
    """Determines when pentesting is truly complete based on deterministic test states."""

    def __init__(self, state_store: CoverageStateStore):
        self.state_store = state_store
        
    def is_converged(self) -> bool:
        """
        Check if the pentest has reached convergence.
        Convergence is achieved when ALL initialized tests are in a terminal state.
        Terminal states: CONFIRMED, REJECTED, BLOCKED, NOT_APPLICABLE
        """
        states = self.state_store.get_all_states()
        if not states:
            # If no states exist, we haven't even started or initialized.
            return False
            
        terminal_states = [TestState.CONFIRMED, TestState.REJECTED, TestState.BLOCKED, TestState.NOT_APPLICABLE]
        
        non_terminal_tests = []
        for test_id, state in states.items():
            if state not in terminal_states:
                non_terminal_tests.append(test_id)
                
        if non_terminal_tests:
            logger.debug(f"Not converged. {len(non_terminal_tests)} tests remaining in non-terminal states.")
            return False
            
        logger.info("Pentest converged. All deterministic coverage tests reached terminal states.")
        return True
