
import logging
from typing import List
from pydantic import BaseModel
from core.common.schemas import ExecutionState

logger = logging.getLogger(__name__)


class ProgressSnapshot(BaseModel):
    completed_tasks_count: int
    failed_tasks_count: int
    blocked_tasks_count: int
    knowledge_count: int
    evidence_count: int
    findings_count: int
    relationships_count: int


class ProgressEvaluator:

    def __init__(self):
        self.snapshots: List[ProgressSnapshot] = []
        self.no_progress_streak = 0

    def take_snapshot(self, state: ExecutionState) -> ProgressSnapshot:
        completed = len(state.tasks_completed)
        failed = len(state.tasks_failed)
        blocked = len(state.tasks_blocked)

        knowledge_cnt = sum(state.knowledge_summary.values()) if state.knowledge_summary else 0
        evidence_cnt = sum(state.evidence_summary.values()) if state.evidence_summary else 0
        findings_cnt = len(state.findings) if state.findings else 0

        # Sum relationship/dependency edges in the DAG
        rel_cnt = sum(len(deps) for deps in state.task_dependency_graph.values()) if state.task_dependency_graph else 0

        return ProgressSnapshot(
            completed_tasks_count=completed,
            failed_tasks_count=failed,
            blocked_tasks_count=blocked,
            knowledge_count=knowledge_cnt,
            evidence_count=evidence_cnt,
            findings_count=findings_cnt,
            relationships_count=rel_cnt
        )

    def evaluate_progress(self, current: ProgressSnapshot) -> bool:
        if not self.snapshots:
            self.snapshots.append(current)
            return True

        last = self.snapshots[-1]

        # Meaningful progress has been made if:
        # - More tasks completed successfully
        # - More knowledge entities discovered
        # - More evidence items stored
        # - More findings identified
        # - The dependency graph/relationships count changed
        # Note: just failed/blocked task count increasing alone is NOT progress!
        progress = (
            current.completed_tasks_count > last.completed_tasks_count or
            current.knowledge_count > last.knowledge_count or
            current.evidence_count > last.evidence_count or
            current.findings_count > last.findings_count or
            current.relationships_count != last.relationships_count
        )

        self.snapshots.append(current)

        if progress:
            self.no_progress_streak = 0
            logger.info("[ProgressEvaluator] Meaningful progress detected.")
        else:
            self.no_progress_streak += 1
            logger.warning(
                f"[ProgressEvaluator] NO_PROGRESS_DETECTED: No progress made in this iteration. "
                f"No-progress streak: {self.no_progress_streak}/3"
            )

        return progress
