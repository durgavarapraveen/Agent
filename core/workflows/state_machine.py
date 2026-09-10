
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import uuid

logger = logging.getLogger(__name__)

@dataclass
class WorkflowState:
    name: str
    is_initial: bool = False
    is_terminal: bool = False
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkflowTransition:
    from_state: str
    to_state: str
    action: str
    preconditions: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)

class WorkflowStateMachine:
    def __init__(self, name: str):
        self.name = name
        self.states: Dict[str, WorkflowState] = {}
        self.transitions: List[WorkflowTransition] = []
        self.current_state: Optional[str] = None
        self.history: List[Dict[str, Any]] = []
        self.workflow_id = uuid.uuid4().hex

    def add_state(self, state: WorkflowState):
        self.states[state.name] = state
        if state.is_initial:
            self.current_state = state.name

    def add_transition(self, transition: WorkflowTransition):
        self.transitions.append(transition)

    def step(self, action: str, params: Dict[str, Any]) -> bool:
        """Attempt to step the state machine forward."""
        if not self.current_state:
            logger.error("State machine has no current state.")
            return False

        # Find valid transitions
        valid_transitions = [
            t for t in self.transitions 
            if t.from_state == self.current_state and t.action == action
        ]

        if not valid_transitions:
            logger.warning(f"Invalid transition: {action} from {self.current_state}")
            return False

        transition = valid_transitions[0]
        
        for pre in transition.preconditions:
            if not self._evaluate_precondition(pre, params):
                logger.warning(f"Precondition failed: {pre}")
                return False

        # Execute transition
        old_state = self.current_state
        self.current_state = transition.to_state
        
        # Record history
        self.history.append({
            "from": old_state,
            "to": self.current_state,
            "action": action,
            "params": params
        })
        
        return True

    def rollback(self, steps: int = 1) -> bool:
        """Rollback state for testing out-of-order execution."""
        if len(self.history) < steps:
            return False
            
        for _ in range(steps):
            last_step = self.history.pop()
            self.current_state = last_step["from"]
        return True

    def _evaluate_precondition(self, precondition: str, params: Dict[str, Any]) -> bool:
        """Evaluate a precondition string against params.

        Preconditions use the form ``key=value`` or bare ``key`` (truthy check).
        """
        if "=" in precondition:
            key, expected = precondition.split("=", 1)
            return str(params.get(key.strip(), "")) == expected.strip()
        return bool(params.get(precondition.strip()))

    def get_valid_actions(self) -> List[str]:
        if not self.current_state:
            return []
        return [t.action for t in self.transitions if t.from_state == self.current_state]

    def is_terminal(self) -> bool:
        if not self.current_state:
            return True
        state = self.states.get(self.current_state)
        return state.is_terminal if state else True
