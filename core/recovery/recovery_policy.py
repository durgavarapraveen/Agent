from __future__ import annotations

from enum import Enum
from typing import Dict

from core.failure.failure_taxonomy import FailureType


class RetryAction(Enum):
    RETRY = "retry"
    FALLBACK = "fallback"
    BLOCK = "block"
    LOG_AND_CONTINUE = "log_and_continue"


DEFAULT_POLICY: Dict[FailureType, RetryAction] = {
    FailureType.NETWORK_ERROR: RetryAction.RETRY,
    FailureType.TIMEOUT: RetryAction.RETRY,
    FailureType.AUTHORIZATION_ERROR: RetryAction.BLOCK,
    FailureType.SCHEMA_ERROR: RetryAction.BLOCK,
    FailureType.NO_EXECUTOR: RetryAction.BLOCK,
    FailureType.TOOL_NOT_FOUND: RetryAction.FALLBACK,
    FailureType.TOOL_EXECUTION_ERROR: RetryAction.FALLBACK,
    FailureType.LLM_REFUSAL: RetryAction.LOG_AND_CONTINUE,
    FailureType.VALIDATION_ERROR: RetryAction.LOG_AND_CONTINUE,
    FailureType.DUPLICATE_TASK: RetryAction.LOG_AND_CONTINUE,
    FailureType.DISCOVERY_INSUFFICIENT: RetryAction.LOG_AND_CONTINUE,
}

MAX_RETRIES: Dict[FailureType, int] = {
    FailureType.NETWORK_ERROR: 3,
    FailureType.TIMEOUT: 2,
}


class RecoveryPolicy:

    def __init__(self, overrides: Dict[FailureType, RetryAction] | None = None) -> None:
        self._policy = dict(DEFAULT_POLICY)
        if overrides:
            self._policy.update(overrides)

    def get_action(self, failure_type: FailureType) -> RetryAction:
        return self._policy.get(failure_type, RetryAction.LOG_AND_CONTINUE)

    def get_max_retries(self, failure_type: FailureType) -> int:
        return MAX_RETRIES.get(failure_type, 1)
