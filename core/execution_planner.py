"""
Execution Planner.
Validates proposed LLM tool strategies against ToolKnowledgeStore, scope policies, and risk constraints.
"""

import logging
from typing import List, Dict, Any, Optional
from core.tool_intelligence import ToolProfile, TargetContext
from core.tool_knowledge_store import ToolKnowledgeStore
from core.tool_adapter import ToolAdapter, ToolInvocation
from core.exceptions import ToolValidationError
from core.authorization import TargetScopeValidator
from core.schemas import TaskSpec

logger = logging.getLogger(__name__)


class ExecutionPlanner:
    """Validates and creates concrete execution plans from LLM strategies"""

    def __init__(self, store: Optional[ToolKnowledgeStore] = None):
        self.store = store or ToolKnowledgeStore.get_instance()

    def plan_execution(
        self,
        strategy_steps: List[Dict[str, Any]],
        task_spec: TaskSpec,
        target_context: TargetContext,
        allowed_profiles: List[ToolProfile]
    ) -> List[ToolInvocation]:
        """
        Validate proposed steps and build safe ToolInvocation list.
        Logs EXECUTION_STRATEGY_CREATED and EXECUTION_PLAN_VALIDATED.
        """
        allowed_names = {p.name.lower().strip() for p in allowed_profiles}
        logger.info(f"EXECUTION_STRATEGY_CREATED: steps={[s.get('tool') for s in strategy_steps]} objective='{task_spec.objective[:60]}'")

        validated_invocations: List[ToolInvocation] = []

        for step in strategy_steps:
            raw_tool = step.get("tool", "").lower().strip()
            if not raw_tool:
                continue

            # 1. Reject generic shell tools
            if raw_tool in ToolAdapter.FORBIDDEN_TOOLS:
                logger.error(f"EXECUTION_PLAN_REJECTED: Generic shell tool '{raw_tool}' is forbidden")
                raise ToolValidationError(f"Tool '{raw_tool}' is a forbidden generic shell tool")

            # 2. Verify tool exists in ToolKnowledgeStore
            profile = self.store.get_tool(raw_tool)
            if not profile:
                logger.error(f"EXECUTION_PLAN_REJECTED: Tool '{raw_tool}' is not registered in ToolKnowledgeStore")
                raise ToolValidationError(f"Tool '{raw_tool}' is not registered in ToolKnowledgeStore")

            # 3. Check if tool is allowed for this capability
            if raw_tool not in allowed_names and profile.name.lower() not in allowed_names:
                # If tool has the capability, dynamically allow
                if task_spec.capability.value not in profile.capabilities and "all" not in profile.capabilities:
                    logger.warning(f"Tool '{raw_tool}' does not explicitly match capability '{task_spec.capability.value}'")

            # 4. Validate target scope
            target_to_use = target_context.url or target_context.hostname or target_context.raw
            TargetScopeValidator.get().validate(target_to_use)

            # 5. Extract and normalize parameters
            params = dict(step.get("params", {}))
            params["target"] = target_to_use
            if target_context.port and "port" not in params:
                params["port"] = target_context.port

            inv = ToolInvocation(
                tool=profile.name,
                operation=task_spec.capability.value,
                params=params,
                target=target_to_use
            )

            # Validate parameters through ToolAdapter dry-run
            try:
                ToolAdapter.adapt(inv)
                validated_invocations.append(inv)
            except Exception as e:
                logger.error(f"EXECUTION_PLAN_REJECTED: ToolAdapter validation failed for '{raw_tool}': {e}")
                raise ToolValidationError(f"Parameter validation failed for tool '{raw_tool}': {e}")

        logger.info(f"EXECUTION_PLAN_VALIDATED: validated_tools={[inv.tool for inv in validated_invocations]}")
        return validated_invocations
