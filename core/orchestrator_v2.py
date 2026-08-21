"""
Orchestration layer - coordinates all components.
Framework drives execution, enforces policy, manages state.
"""

import logging
import json
from typing import Dict, List, Optional
from datetime import datetime
from schemas import (
    BrainDecision, BrainDecisionAction, ToolResult, AgentResult,
    TaskStatus, ExecutionMetrics
)
from task_manager import TaskManager
from scheduler import Scheduler
from tool_definitions import CapabilityRegistry
from policy_validator import PolicyValidator, ScopeValidator
from error_classifier import ErrorClassifier
from result_normalizers import NormalizerFactory
from stores import KnowledgeStore, EvidenceStore, FindingStore
from central_brain_v2 import CentralBrainV2

logger = logging.getLogger(__name__)


class OrchestratorV2:
    """
    Orchestration engine - deterministic execution framework.
    Coordinates Brain decisions, task execution, policy enforcement.
    """
    
    def __init__(self, target: str, scope: Dict = None):
        self.target = target
        self.scope = scope or {"authorized_targets": [target]}
        self.start_time = datetime.now()
        
        # Core components
        self.brain = CentralBrainV2(target, scope)
        self.task_manager = self.brain.task_manager
        self.scheduler = Scheduler(self.task_manager)
        
        # Tool and policy management
        self.tool_registry = CapabilityRegistry()
        self.policy_validator = PolicyValidator(
            self.scope.get("authorized_targets", [target])
        )
        self.scope_validator = ScopeValidator(
            self.scope.get("authorized_targets", [target])
        )
        self.error_classifier = ErrorClassifier()
        
        # Metrics
        self.metrics = ExecutionMetrics()
        self.iterations = 0
        self.max_iterations = 50
    
    def run(self) -> Dict:
        """Main execution loop"""
        logger.info(f"[Orchestrator] Starting execution for {self.target}")
        
        while self.iterations < self.max_iterations:
            self.iterations += 1
            
            # 1. Get current state
            state = self.brain.get_execution_state()
            
            # 2. Brain makes decision
            decision = self.brain.make_decision(state)
            logger.info(f"[Orchestrator] Iteration {self.iterations}: {decision.action.value}")
            
            # 3. Execute decision
            if decision.action == BrainDecisionAction.SPAWN_AGENTS:
                self._execute_spawn_agents(decision)
            
            elif decision.action == BrainDecisionAction.RUN_TASK:
                self._execute_run_task(decision)
            
            elif decision.action == BrainDecisionAction.WAIT:
                self._execute_wait(decision)
            
            elif decision.action == BrainDecisionAction.COMPLETE:
                logger.info("[Orchestrator] Brain decided to complete")
                return self._generate_final_report()
            
            elif decision.action == BrainDecisionAction.BLOCKED:
                logger.error("[Orchestrator] Brain detected blocking condition")
                return self._generate_final_report()
            
            elif decision.action == BrainDecisionAction.REPLAN:
                logger.info("[Orchestrator] Brain replanning")
                continue
        
        logger.warning("[Orchestrator] Max iterations reached")
        return self._generate_final_report()
    
    def _execute_spawn_agents(self, decision: BrainDecision) -> None:
        """Schedule multiple tasks from decision"""
        if not decision.tasks:
            logger.warning("[Orchestrator] spawn_agents but no tasks")
            return
        
        # Schedule tasks through scheduler
        created_tasks = self.scheduler.schedule_tasks(decision.tasks)
        
        logger.info(f"[Orchestrator] Scheduled {len(created_tasks)} tasks")
        self.metrics.task_count_total += len(created_tasks)
        
        # Run ready tasks
        ready = self.scheduler.get_next_runnable_tasks()
        for task in ready:
            self._execute_task(task)
    
    def _execute_run_task(self, decision: BrainDecision) -> None:
        """Execute single task"""
        if not decision.tasks:
            return
        
        task_spec = decision.tasks[0]
        task = self.task_manager.get_task(task_spec.task_id)
        self._execute_task(task)
    
    def _execute_task(self, task) -> None:
        """
        Execute a task.
        In real implementation, would spawn agent to execute.
        Here: simulate execution for demonstration.
        """
        try:
            self.task_manager.start_task(task.spec.task_id)
            
            # Simulate agent execution
            logger.info(f"[Orchestrator] Executing task: {task.spec.objective}")
            
            # In production, would invoke agent here
            # For now, mark as completed
            self.task_manager.complete_task(task.spec.task_id)
            self.metrics.task_count_completed += 1
            
            # Process dependencies for dependent tasks
            self.scheduler.process_dependencies()
            
        except Exception as e:
            logger.error(f"[Orchestrator] Task failed: {e}")
            self.task_manager.fail_task(task.spec.task_id, str(e))
            self.metrics.task_count_failed += 1
    
    def _execute_wait(self, decision: BrainDecision) -> None:
        """Wait for tasks to complete"""
        wait_seconds = decision.wait_seconds or 1
        logger.info(f"[Orchestrator] Waiting {wait_seconds}s")
    
    def handle_tool_result(self, task_id: str, tool_result: ToolResult) -> Dict:
        """
        Process tool result.
        Framework normalizes output, stores evidence/knowledge.
        """
        logger.info(f"[Orchestrator] Processing tool result: {tool_result.tool}")
        
        # Classify error if failed
        if tool_result.status == "failed":
            error = self.error_classifier.classify_error(
                tool_result.tool,
                tool_result.exit_code,
                tool_result.stdout,
                tool_result.stderr,
            )
            tool_result.error = error
            self.metrics.tool_count_failed += 1
            
            if error.retryable:
                logger.warning(f"[Orchestrator] Error is retryable: {error.message}")
                return {"retry": True, "error": error.to_dict()}
            else:
                logger.error(f"[Orchestrator] Non-retryable error: {error.message}")
                self.task_manager.fail_task(task_id, error.message)
                return {"retry": False, "error": error.to_dict()}
        
        # Normalize result
        evidence, knowledge_items = NormalizerFactory.normalize_result(tool_result)
        
        # Store evidence
        evidence_id = self.brain.evidence_store.store(evidence)
        tool_result.evidence_id = evidence_id
        
        # Store knowledge
        for item in knowledge_items:
            item.evidence_id = evidence_id
            self.brain.knowledge_store.store(item)
        
        self.metrics.tool_count_success += 1
        self.metrics.knowledge_items_created += len(knowledge_items)
        self.metrics.evidence_items_created += 1
        
        logger.info(f"[Orchestrator] Stored {len(knowledge_items)} knowledge items")
        
        return {
            "success": True,
            "evidence_id": evidence_id,
            "knowledge_count": len(knowledge_items),
        }
    
    def validate_tool_request(self, tool_name: str, 
                             capability: str,
                             target: str,
                             command: Optional[str] = None) -> tuple[bool, Optional[Dict]]:
        """
        Validate tool request before execution.
        Policy enforcement happens here, not in agents.
        """
        
        # Check scope
        authorized, reason = self.policy_validator.validate_scope(target)
        if not authorized:
            logger.error(f"[Orchestrator] Scope violation: {reason}")
            return False, {"error": "SCOPE_VIOLATION", "reason": reason}
        
        # Check command
        if command:
            valid, error_info = self.policy_validator.validate_command(command)
            if not valid:
                logger.error(f"[Orchestrator] Policy rejection: {error_info.message}")
                return False, {"error": "POLICY_REJECTION", "reason": error_info.message}
        
        # Check tool availability
        tools = self.tool_registry.get_tools_for_capability(
            self._parse_capability(capability)
        )
        if not tools:
            logger.error(f"[Orchestrator] No tools for capability: {capability}")
            return False, {"error": "TOOL_UNAVAILABLE", "reason": f"No tools for {capability}"}
        
        return True, None
    
    def _parse_capability(self, capability_str: str):
        """Parse capability string to enum"""
        from schemas import CapabilityType
        try:
            return CapabilityType[capability_str.upper()]
        except:
            return None
    
    def _generate_final_report(self) -> Dict:
        """Generate final execution report"""
        duration = (datetime.now() - self.start_time).total_seconds()
        self.metrics.total_duration_seconds = duration
        
        return {
            "status": "completed",
            "target": self.target,
            "duration_seconds": duration,
            "iterations": self.iterations,
            "metrics": {
                "tasks_total": self.metrics.task_count_total,
                "tasks_completed": self.metrics.task_count_completed,
                "tasks_failed": self.metrics.task_count_failed,
                "tasks_blocked": self.metrics.task_count_blocked,
                "tools_executed": self.metrics.tool_count_total,
                "tools_success": self.metrics.tool_count_success,
                "tools_failed": self.metrics.tool_count_failed,
                "knowledge_items": self.metrics.knowledge_items_created,
                "evidence_items": self.metrics.evidence_items_created,
                "findings": self.metrics.findings_created,
            },
            "knowledge_summary": self.brain.knowledge_store.summarize(),
            "findings": [f.to_dict() for f in self.brain.finding_store.get_all()],
            "execution_state": self.brain.get_execution_state().dict(),
        }
