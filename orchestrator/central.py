import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import uuid4
from pathlib import Path

from core.models import Task, TaskStatus, TaskProposal, Finding, AgentResult, CentralAgentDecision
from core.events import EventType, EventBus, EventLogger
from core.context import ExecutionContext
from orchestrator.planner import Planner
from orchestrator.scheduler import TaskScheduler
from agents.factory import AgentFactory, AgentRegistry
from tools.base import ToolPermission

logger = logging.getLogger(__name__)

class CentralOrchestrator:
    """Central orchestrator - the brain of the system."""
    
    def __init__(self, context: ExecutionContext):
        self.context = context
        self.iteration = 0
        self.max_iterations = 5
        
        # Initialize event system
        self.event_bus = EventBus()
        self.event_logger = EventLogger(self.event_bus)
        context.event_bus = self.event_bus
        context.event_logger = self.event_logger
        
        # Initialize components
        self.planner = Planner(context.llm_provider)
        self.scheduler = TaskScheduler(max_concurrent=context.max_concurrent_agents)
        self.agent_registry = AgentRegistry()
        self.agent_factory = AgentFactory(self.agent_registry)
        
        # Execution state
        self.initial_tasks: List[Task] = []
        self.all_tasks: List[Task] = []
        self.all_findings: List[Finding] = []
        self.all_discoveries: List[Dict[str, Any]] = []
        self.task_proposals: List[TaskProposal] = []
        self.assessment_complete = False
        
        logger.info(f"Central Orchestrator initialized for {context.target}")
    
    async def run(self):
        """Run the security assessment."""
        logger.info("=" * 60)
        logger.info("AUTONOMOUS SECURITY ASSESSMENT")
        logger.info("=" * 60)
        logger.info(f"Target: {self.context.target}")
        logger.info(f"Mode: {self.context.mode}")
        logger.info(f"Objective: {self.context.objective}")
        logger.info("=" * 60)
        
        try:
            # Create initial plan
            await self._create_initial_plan()
            
            # Main orchestration loop
            while not self.assessment_complete and self.iteration < self.max_iterations:
                self.iteration += 1
                logger.info(f"\n>>> ITERATION {self.iteration}")
                
                # Execute tasks
                await self._execute_tasks()
                
                # Process results
                await self._process_task_results()
                
                # Evaluate if more work needed
                if await self._should_continue():
                    await self._replan()
                else:
                    self.assessment_complete = True
                
                # Check global timeout
                if self.context.is_timeout_exceeded():
                    logger.warning("Global timeout exceeded")
                    break
            
            # Finalize assessment
            await self._finalize_assessment()
        
        except Exception as e:
            logger.error(f"Orchestration failed: {e}", exc_info=True)
            raise
    
    async def _create_initial_plan(self):
        """Create the initial task plan."""
        logger.info("Creating initial plan...")
        
        # Determine target type
        if self.context.mode == "SOURCE":
            target_type = "SOURCE"
        elif self.context.mode == "WEB":
            target_type = "WEB"
        else:
            target_type = "DEMO"
        
        # Create initial tasks
        initial_tasks = await self.planner.create_initial_plan(
            self.context.objective,
            target_type
        )
        
        self.initial_tasks = initial_tasks
        self.all_tasks.extend(initial_tasks)
        
        # Queue tasks
        for task in initial_tasks:
            await self.scheduler.submit_task(task)
            await self.event_logger.log_event(
                EventType.TASK_CREATED,
                task.task_id,
                {"capability": task.capability, "priority": task.priority}
            )
        
        logger.info(f"Created {len(initial_tasks)} initial tasks")
    
    async def _execute_tasks(self):
        """Execute ready tasks."""
        logger.info(f"Executing tasks (queued: {self.scheduler.get_queued_count()})...")
        
        async def task_executor(task: Task) -> AgentResult:
            # Create agent for task
            agent = await self.agent_factory.create_agent(task.capability, self.context)
            
            if not agent:
                logger.error(f"Failed to create agent for capability: {task.capability}")
                return AgentResult(status="failed")
            
            # Execute task
            task.assigned_agent_id = agent.agent_id
            result = await agent.execute_task(task)
            
            return result
        
        # Schedule tasks for execution
        results = await self.scheduler.schedule_work(
            task_executor,
            max_tasks=self.context.max_concurrent_agents
        )
        
        logger.info(f"Executed {len(results)} tasks")
    
    async def _process_task_results(self):
        """Process results from completed tasks."""
        logger.info("Processing task results...")
        
        for task in self.scheduler.completed_tasks:
            if task.result:
                result = task.result
                
                # Store discoveries
                self.all_discoveries.extend(result.discoveries)
                
                # Store findings
                self.all_findings.extend(result.findings)
                
                # Collect task proposals
                self.task_proposals.extend(result.task_proposals)
                
                logger.info(f"Task {task.task_id}: "
                           f"{len(result.findings)} findings, "
                           f"{len(result.discoveries)} discoveries, "
                           f"{len(result.task_proposals)} proposals")
        
        logger.info(f"Total discoveries: {len(self.all_discoveries)}")
        logger.info(f"Total findings: {len(self.all_findings)}")
        logger.info(f"Total proposals: {len(self.task_proposals)}")
    
    async def _should_continue(self) -> bool:
        """Determine if more work is needed."""
        # Continue if we have task proposals and haven't hit iteration limit
        has_proposals = len(self.task_proposals) > 0
        has_capacity = self.iteration < self.max_iterations
        
        return has_proposals and has_capacity
    
    async def _replan(self):
        """Replan based on discoveries."""
        logger.info("\n>>> REPLANNING")
        
        await self.event_logger.log_event(
            EventType.REPLAN_STARTED,
            "central_orchestrator",
            {"iteration": self.iteration}
        )
        
        # Create tasks from proposals
        new_tasks = await self.planner.create_tasks_from_proposals(self.task_proposals)
        
        # Clear proposals
        self.task_proposals = []
        
        # Queue new tasks
        for task in new_tasks:
            await self.scheduler.submit_task(task)
            self.all_tasks.append(task)
            await self.event_logger.log_event(
                EventType.TASK_CREATED,
                task.task_id,
                {"capability": task.capability, "from_proposal": True}
            )
        
        logger.info(f"Created {len(new_tasks)} tasks from proposals")
        
        await self.event_logger.log_event(
            EventType.REPLAN_COMPLETED,
            "central_orchestrator",
            {"tasks_created": len(new_tasks)}
        )
    
    async def _finalize_assessment(self):
        """Finalize the assessment."""
        logger.info("\n>>> FINALIZING ASSESSMENT")
        
        # Create validation tasks
        validation_tasks = await self.planner.create_validation_plan(self.all_findings)
        
        if validation_tasks:
            logger.info(f"Creating {len(validation_tasks)} validation tasks")
            for task in validation_tasks:
                await self.scheduler.submit_task(task)
                self.all_tasks.append(task)
        
        # Create correlation tasks
        correlation_tasks = await self.planner.create_correlation_plan(self.all_findings)
        
        if correlation_tasks:
            logger.info(f"Creating {len(correlation_tasks)} correlation tasks")
            for task in correlation_tasks:
                await self.scheduler.submit_task(task)
                self.all_tasks.append(task)
        
        # Create reporting task
        reporting_tasks = await self.planner.create_reporting_plan()
        
        for task in reporting_tasks:
            await self.scheduler.submit_task(task)
            self.all_tasks.append(task)
        
        # Execute final tasks
        logger.info("Executing validation/correlation/reporting tasks...")
        
        async def final_executor(task: Task) -> AgentResult:
            agent = await self.agent_factory.create_agent(task.capability, self.context)
            if not agent:
                return AgentResult(status="failed")
            return await agent.execute_task(task)
        
        await self.scheduler.schedule_work(final_executor)
        
        # Mark complete
        self.context.mark_complete()
        
        # Print summary
        await self._print_summary()
        
        # Generate report
        await self._generate_report()
    
    async def _print_summary(self):
        """Print execution summary."""
        logger.info("\n" + "=" * 60)
        logger.info("ASSESSMENT COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Duration: {self.context.get_duration_seconds():.1f}s")
        logger.info(f"Iterations: {self.iteration}")
        logger.info(f"Agents created: {len(self.agent_factory.created_agents)}")
        logger.info(f"Tasks executed: {self.scheduler.get_completed_count()}")
        logger.info(f"Discoveries: {len(self.all_discoveries)}")
        logger.info(f"Findings: {len(self.all_findings)}")
        logger.info(f"  - Critical: {len([f for f in self.all_findings if f.severity.value == 'CRITICAL'])}")
        logger.info(f"  - High: {len([f for f in self.all_findings if f.severity.value == 'HIGH'])}")
        logger.info(f"  - Medium: {len([f for f in self.all_findings if f.severity.value == 'MEDIUM'])}")
        logger.info("=" * 60)
    
    async def _generate_report(self):
        """Generate final report."""
        try:
            from reporting.generator import ReportGenerator
            
            generator = ReportGenerator(self.context, self.all_findings, self.all_discoveries)
            await generator.generate()
            logger.info("Report generation complete")
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
