"""
Refactored Central Brain V2
- Uses structured BrainDecision schema
- Does not control framework state
- Plans and reasons, framework executes
"""

import logging
import json
from typing import Dict, List, Optional
from datetime import datetime
from core.schemas import (
    BrainDecision, BrainDecisionAction, ExecutionState, TaskSpec,
    SuccessCriterion, SuccessCriterionType, CapabilityType
)
from core.task_manager import TaskManager
from orchestrator.scheduler import Scheduler
from core.stores import KnowledgeStore, EvidenceStore, FindingStore
from core.context_resolver import ContextResolver

logger = logging.getLogger(__name__)


class CentralBrainV2:
    """
    Refactored brain - reasoning engine only.
    Framework owns execution state, scheduling, policy.
    """
    
    def __init__(self, target: str, scope: Dict = None):
        self.target = target
        self.scope = scope or {}
        self.start_time = datetime.now()
        self.authorized_scope = (scope or {}).get("authorized_targets", [target])
        self.execution_count = 0
        self.max_iterations = 100
        
        # Stores (shared)
        self.knowledge_store = KnowledgeStore()
        self.evidence_store = EvidenceStore()
        self.finding_store = FindingStore()
        
        # Framework components
        self.task_manager = TaskManager()
        self.scheduler = Scheduler(self.task_manager)
        self.context_resolver = ContextResolver(self.knowledge_store)
    
    def plan_reconnaissance(self, state: ExecutionState) -> BrainDecision:
        """
        Reason about reconnaissance tasks.
        Returns structured decision, not task objects.
        """
        
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
        """
        Central decision point.
        Analyzes execution state, decides next action.
        """
        
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
        """Plan vulnerability analysis phase"""
        # This would implement deeper analysis logic
        return BrainDecision(
            action=BrainDecisionAction.COMPLETE,
            reason="Analysis planning not yet implemented"
        )
    
    def _determine_phase(self, state: ExecutionState) -> str:
        """Determine current phase of execution"""
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
    
    def get_execution_state(self) -> ExecutionState:
        """
        Build structured state for Brain decision-making.
        Not raw logs or context, structured facts.
        """
        # Separate tasks by status
        all_tasks = self.task_manager.get_all_tasks()
        completed = [t.spec for t in all_tasks if t.status.value == "COMPLETED"]
        running = [t.spec for t in all_tasks if t.status.value == "RUNNING"]
        failed = [t.spec.task_id for t in all_tasks if t.status.value == "FAILED"]
        blocked = [t.spec.task_id for t in all_tasks if t.status.value == "BLOCKED"]
        
        return ExecutionState(
            target=self.target,
            scope=self.scope,
            tasks_completed=completed,
            tasks_running=running,
            tasks_failed=failed,
            tasks_blocked=blocked,
            task_dependency_graph=self.task_manager.get_dependency_graph(),
            knowledge_summary=self.knowledge_store.summarize(),
            evidence_summary=self.evidence_store.to_dict(),
            findings=self.finding_store.get_all(),
            available_capabilities=[
                CapabilityType.DNS_ENUMERATION,
                CapabilityType.PORT_SCANNING,
                CapabilityType.TLS_ANALYSIS,
                CapabilityType.TECHNOLOGY_FINGERPRINTING,
                CapabilityType.HTTP_ANALYSIS,
            ],
            objectives=self.scope.get("objectives", []),
        )
    
    def to_dict(self) -> Dict:
        """Serialize brain state"""
        return {
            "execution_count": self.execution_count,
            "target": self.target,
            "scope": self.scope,
            "knowledge": self.knowledge_store.to_dict(),
            "evidence": self.evidence_store.to_dict(),
            "findings": self.finding_store.to_dict(),
            "tasks": self.task_manager.to_dict(),
            "start_time": self.start_time.isoformat(),
        }
