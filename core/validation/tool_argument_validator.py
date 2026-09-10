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

    def _resolve_tool(self, tool_name: str):
        reg = self._registry
        for getter in ("get_tool", "get"):
            fn = getattr(reg, getter, None)
            if callable(fn):
                try:
                    tool = fn(tool_name)
                    if tool is not None:
                        return tool
                except Exception:
                    pass
        for attr in ("available_tools", "tools"):
            d = getattr(reg, attr, None)
            if isinstance(d, dict) and tool_name in d:
                return d[tool_name]
        return None

    def _list_available(self) -> List[str]:
        reg = self._registry
        fn = getattr(reg, "get_all_available_tools", None)
        if callable(fn):
            try:
                return [t.name if hasattr(t, 'name') else str(t) for t in fn()]
            except Exception:
                pass
        for attr in ("available_tools", "tools"):
            d = getattr(reg, attr, None)
            if isinstance(d, dict) and d:
                return list(d.keys())
        return []

    def validate(self, tool_name: str, target: str,
                 args: Dict[str, Any],
                 capability: str = "",
                 required_args: Optional[List[str]] = None) -> None:

        if self._registry and tool_name:
            tool = self._resolve_tool(tool_name)
            if tool is None:
                available = self._list_available()
                # Only reject when we actually have a populated registry to
                # compare against; an empty list means the registry hasn't been
                # introspected yet, so we must not block execution.
                if available:
                    raise ToolArgumentValidationError(
                        f"Tool '{tool_name}' not found. Available: {sorted(available)[:10]}",
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
