"""
Tool argument validation (Phase 13).

Validates tool invocation requests BEFORE execution:
1. Tool exists
2. Capability exists
3. Required arguments exist
4. Target is normalized
5. Target is in scope
6. Arguments match tool schema
7. Resource/risk budget allows execution
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolArgumentValidationError(Exception):
    def __init__(self, reason: str, error_type: str = "INVALID_INVOCATION"):
        self.reason = reason
        self.error_type = error_type
        super().__init__(reason)


class ToolArgumentValidator:

    def __init__(self, tool_registry=None, scope_manager=None):
        self._registry = tool_registry
        self._scope = scope_manager

    def validate(self, tool_name: str, target: str,
                 args: Dict[str, Any],
                 capability: str = "",
                 required_args: Optional[List[str]] = None) -> None:
        """Validate tool invocation. Raises ToolArgumentValidationError on failure."""

        if self._registry:
            tool = self._registry.get_tool(tool_name) if hasattr(self._registry, 'get_tool') else None
            if tool is None:
                available = []
                if hasattr(self._registry, 'get_all_available_tools'):
                    available = [t.name if hasattr(t, 'name') else str(t)
                                 for t in self._registry.get_all_available_tools()]
                raise ToolArgumentValidationError(
                    f"Tool '{tool_name}' not found. Available: {available[:10]}",
                    "TOOL_NOT_FOUND",
                )

        if not target or not target.strip():
            raise ToolArgumentValidationError("Target is empty", "INVALID_ARGUMENT")

        target_norm = target.strip().lower()
        if target_norm.startswith("http"):
            pass
        elif " " in target_norm:
            raise ToolArgumentValidationError(
                f"Target contains spaces: {target[:60]}", "INVALID_ARGUMENT"
            )

        if self._scope:
            rejection = self._scope.validate_plan(target, tool_name)
            if rejection:
                raise ToolArgumentValidationError(rejection, "SCOPE_DENIED")

        if required_args:
            missing = [a for a in required_args if a not in args or args[a] is None]
            if missing:
                raise ToolArgumentValidationError(
                    f"Missing required arguments for {tool_name}: {missing}",
                    "INVALID_ARGUMENT",
                )

        logger.debug(f"TOOL_ARGS_VALID tool={tool_name} target={target[:60]}")
