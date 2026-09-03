from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class TaskState(Enum):
    CREATED = "created"
    WAITING_DEPENDENCY = "waiting_dependency"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RETRY_PENDING = "retry_pending"


VALID_TRANSITIONS: Dict[TaskState, Set[TaskState]] = {
    TaskState.CREATED: {TaskState.WAITING_DEPENDENCY, TaskState.READY},
    TaskState.WAITING_DEPENDENCY: {TaskState.READY, TaskState.FAILED},
    TaskState.READY: {TaskState.RUNNING},
    TaskState.RUNNING: {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.RETRY_PENDING},
    TaskState.SUCCEEDED: set(),
    TaskState.FAILED: {TaskState.RETRY_PENDING},
    TaskState.RETRY_PENDING: {TaskState.READY, TaskState.FAILED},
}


class TaskStateMachine:

    def __init__(self, task_id: str, initial_state: TaskState = TaskState.CREATED) -> None:
        self.task_id = task_id
        self.state = initial_state

    def can_transition(self, new_state: TaskState) -> bool:
        return new_state in VALID_TRANSITIONS.get(self.state, set())

    def transition(self, new_state: TaskState) -> bool:
        if not self.can_transition(new_state):
            allowed = [s.value for s in VALID_TRANSITIONS.get(self.state, set())]
            raise ValueError(
                f"Invalid transition {self.state.value} -> {new_state.value}. "
                f"Valid transitions from {self.state.value}: {allowed}"
            )
        self.state = new_state
        return True
