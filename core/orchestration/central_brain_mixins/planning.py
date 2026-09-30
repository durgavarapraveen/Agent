from __future__ import annotations

import logging

from core.common.schemas import (
    BrainDecision,
    BrainDecisionAction,
    CapabilityType,
    ExecutionState,
    SuccessCriterion,
    SuccessCriterionType,
    TaskSpec,
)

logger = logging.getLogger(__name__)


class PlanningMixin:
    """Deterministic planning decisions: make_decision dispatch and the
    per-phase planners (reconnaissance, analysis) that build TaskSpecs, plus
    _determine_phase. Pure functions of ExecutionState; no phase-state mutation.
    Extracted from CentralBrain.
    """

    def plan_reconnaissance(self, state: ExecutionState) -> BrainDecision:
        
        # What do we already know?
        hosts_known = len(self.knowledge_store.get_by_type("host"))
        ports_known = len(self.knowledge_store.get_by_type("port"))
        services_known = len(self.knowledge_store.get_by_type("service"))
        
        # What should we investigate?
        tasks = []
        
        # Stage 1: DNS if no hosts known
        if hosts_known == 0:
            tasks.append(TaskSpec(
                objective=f"Enumerate DNS records for {self.target}",
                capability=CapabilityType.DNS_ENUMERATION,
                inputs={"domain": self.target},
                context_requirements=["hosts"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="host"
                    )
                ],
                timeout_seconds=300,
                max_steps=5,
            ))
        
        # Stage 2: Port scan discovered hosts
        elif hosts_known > 0 and ports_known == 0:
            tasks.append(TaskSpec(
                objective="Scan discovered hosts for open ports",
                capability=CapabilityType.PORT_SCANNING,
                inputs={"targets": [h["host"] for h in self.context_resolver.resolve_hosts(self.authorized_scope)]},
                context_requirements=["hosts"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="port"
                    )
                ],
                timeout_seconds=600,
                max_steps=8,
            ))
        
        # Stage 3: Technology fingerprinting
        elif ports_known > 0 and services_known == 0:
            tasks.append(TaskSpec(
                objective="Fingerprint technologies on discovered services",
                capability=CapabilityType.TECHNOLOGY_FINGERPRINTING,
                inputs={"ports": self.context_resolver.resolve_ports()},
                context_requirements=["ports"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="technology"
                    )
                ],
                timeout_seconds=300,
                max_steps=8,
            ))
        
        else:
            # Recon complete
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                thought="Reconnaissance phase complete - hosts, ports, technologies discovered",
                reason="Sufficient reconnaissance data collected"
            )
        
        if tasks:
            return BrainDecision(
                action=BrainDecisionAction.SPAWN_AGENTS,
                thought=f"Spawning {len(tasks)} reconnaissance task(s)",
                tasks=tasks,
            )
        
        return BrainDecision(
            action=BrainDecisionAction.WAIT,
            thought="Waiting for reconnaissance tasks to complete",
            wait_seconds=5,
        )

    def make_decision(self, state: ExecutionState) -> BrainDecision:
        
        # Safety check
        if self.execution_count >= self.max_iterations:
            logger.warning("[Brain] Max iterations reached, completing")
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                reason="Max execution iterations reached"
            )
        
        self.execution_count += 1
        
        # Check if all objectives completed
        completed_count = len(state.tasks_completed)
        failed_count = len(state.tasks_failed)
        blocked_count = len(state.tasks_blocked)
        running_count = len(state.tasks_running)
        
        logger.info(f"[Brain] Iteration {self.execution_count}: "
                    f"completed={completed_count}, running={running_count}, "
                    f"failed={failed_count}, blocked={blocked_count}")
        
        # Check for blocking issues
        if blocked_count > 0 and running_count == 0 and completed_count == 0:
            return BrainDecision(
                action=BrainDecisionAction.BLOCKED,
                reason="Tasks blocked and no progress being made"
            )
        
        # Phase-based decision
        phase = self._determine_phase(state)
        
        if phase == "recon":
            return self.plan_reconnaissance(state)
        elif phase == "analysis":
            return self.plan_analysis(state)
        else:
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                reason="No more phases to execute"
            )

    def plan_analysis(self, state: ExecutionState) -> BrainDecision:
        # This would implement deeper analysis logic
        return BrainDecision(
            action=BrainDecisionAction.COMPLETE,
            reason="Analysis planning not yet implemented"
        )

    def _determine_phase(self, state: ExecutionState) -> str:
        hosts_known = len(self.knowledge_store.get_by_type("host"))
        ports_known = len(self.knowledge_store.get_by_type("port"))
        services_known = len(self.knowledge_store.get_by_type("service"))
        
        if hosts_known == 0:
            return "recon"
        elif ports_known == 0:
            return "recon"
        elif services_known == 0:
            return "recon"
        else:
            return "analysis"
