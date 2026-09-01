from typing import Dict
from core.coverage.test_definition import TestState


class CoverageStateStore:
    """Manages the current tracking status of all coverage tests."""
    
    def __init__(self):
        self.test_states: Dict[str, TestState] = {}
        
    def init_test(self, test_id: str, initial_state: TestState):
        """Initialize a test state if not present."""
        if test_id not in self.test_states:
            self.test_states[test_id] = initial_state
            
    def update_test_state(self, test_id: str, new_state: TestState):
        """Update the state of a test."""
        self.test_states[test_id] = new_state
        
    def get_test_state(self, test_id: str) -> TestState:
        """Get the current state of a test."""
        return self.test_states.get(test_id, TestState.NOT_TESTED)
        
    def get_all_states(self) -> Dict[str, TestState]:
        """Get states for all tests."""
        return self.test_states
