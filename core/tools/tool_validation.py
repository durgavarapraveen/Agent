"""
Tool Invocation Validator layer.
Ensures tool execution is safe, authorized, and syntactically valid.
"""

import logging
from typing import Dict, Any
from core.common.exceptions import ToolValidationError
from core.security.authorization import TargetScopeValidator

logger = logging.getLogger(__name__)


class ToolInvocationValidator:
    """Validates tool invocation requests before execution"""

    FORBIDDEN_TOOLS = {"bash", "sh", "cmd", "powershell", "zsh"}

    def __init__(self, registry: Any):
        self.registry = registry

    def validate(self, tool_name: str, params: Dict[str, Any]) -> None:
        """Validate invocation parameters and authorization"""
        tool_name_clean = tool_name.lower().strip()
        logger.info(f"TOOL_INVOCATION_REQUESTED: tool={tool_name_clean}")

        # 0. Reject generic shell tools
        if tool_name_clean in self.FORBIDDEN_TOOLS:
            logger.error(f"TOOL_INVOCATION_REJECTED: generic shell tool '{tool_name_clean}' forbidden")
            raise ToolValidationError(
                f"Tool '{tool_name_clean}' is a generic shell tool and cannot be invoked directly. "
                "Use structured domain tools."
            )

        # 1. Validate tool existence
        tool = None
        if hasattr(self.registry, "get"):
            tool = self.registry.get(tool_name)
        elif hasattr(self.registry, "get_tool"):
            tool = self.registry.get_tool(tool_name)
            
        if not tool:
            logger.error(f"TOOL_INVOCATION_REJECTED: tool '{tool_name}' not registered")
            raise ToolValidationError(f"Tool '{tool_name}' is not registered in ToolRegistry")

        # 2. Extract target if present and check scope
        target = params.get("target") or params.get("url") or params.get("domain") or params.get("host")
        if target:
            TargetScopeValidator.get().validate(target)

        # 3. Validate timeout values
        timeout = params.get("timeout")
        if timeout is not None:
            try:
                t_val = int(timeout)
                if t_val <= 0 or t_val > 1800:
                    logger.error(f"TOOL_INVOCATION_REJECTED: invalid timeout {t_val}")
                    raise ToolValidationError(f"Timeout {t_val} is out of bounds (1-1800s)")
            except ValueError:
                logger.error("TOOL_INVOCATION_REJECTED: timeout must be integer")
                raise ToolValidationError("Timeout parameter must be an integer")

        # 4. Command injection safety checks
        command = params.get("command")
        if command:
            if not isinstance(command, str):
                logger.error("TOOL_INVOCATION_REJECTED: command must be string")
                raise ToolValidationError("Command parameter must be a string")

            # Check safe patterns via PolicyValidator
            from core.security.policy_validator import PolicyValidator
            scope = TargetScopeValidator.get().authorized_scope
            policy = PolicyValidator(scope)
            cmd_ok, err = policy.validate_command(command)
            if not cmd_ok:
                logger.error(f"TOOL_INVOCATION_REJECTED: command rejected by policy: {err.message if err else 'blocked'}")
                raise ToolValidationError(err.message if err else "Command blocked by security policies")

            # Centralized command target validation
            TargetScopeValidator.get().extract_and_validate_command(command)

        logger.info(f"TOOL_INVOCATION_VALIDATED: tool={tool_name_clean}")
