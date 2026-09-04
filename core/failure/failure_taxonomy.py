from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional


class FailureType(Enum):
    AUTHORIZATION_ERROR = "authorization_error"
    SCHEMA_ERROR = "schema_error"
    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_EXECUTION_ERROR = "tool_execution_error"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    VALIDATION_ERROR = "validation_error"
    LLM_REFUSAL = "llm_refusal"
    NO_EXECUTOR = "no_executor"
    DISCOVERY_INSUFFICIENT = "discovery_insufficient"
    DUPLICATE_TASK = "duplicate_task"


class FailureClassifier:

    _PATTERNS = {
        FailureType.NETWORK_ERROR: ["ConnectionError", "ConnectionRefused", "ConnectionReset", "DNS", "socket", "ECONNREFUSED"],
        FailureType.TIMEOUT: ["Timeout", "timed out", "deadline exceeded"],
        FailureType.AUTHORIZATION_ERROR: ["403", "Forbidden", "unauthorized", "401", "permission denied"],
        FailureType.LLM_REFUSAL: ["refusal", "cannot assist", "I cannot", "not allowed", "inappropriate"],
        FailureType.SCHEMA_ERROR: ["schema", "validation", "missing required", "invalid input"],
        FailureType.TOOL_NOT_FOUND: ["not found", "NO_EXECUTOR", "no executor", "command not found"],
        FailureType.DUPLICATE_TASK: ["duplicate", "already exists", "already recorded"],
    }

    def classify(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> FailureType:
        ctx = context or {}
        error_msg = str(error).lower()
        error_code = ctx.get("error_code", "")

        if error_code == "NO_EXECUTOR":
            return FailureType.NO_EXECUTOR

        for failure_type, patterns in self._PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in error_msg:
                    return failure_type

        return FailureType.TOOL_EXECUTION_ERROR
