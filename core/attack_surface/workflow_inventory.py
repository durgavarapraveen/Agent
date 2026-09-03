from typing import List, Dict
from core.domain.asset import Workflow
from core.domain.request import CapturedRequest
import logging
import uuid

logger = logging.getLogger(__name__)

class WorkflowInventory:
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        
    def add_workflow(self, workflow: Workflow):
        self.workflows[workflow.name] = workflow
        
    def discover_workflows_from_requests(self, requests: List[CapturedRequest]) -> List[Workflow]:
        """
        Group real captured requests into workflows by session, ordered by time.
        A workflow is the ordered sequence of requests sharing a session_id. No
        fabricated data — only actual captured requests are grouped.
        """
        if not requests:
            return []

        # Bucket requests by their real session identifier.
        by_session: Dict[str, List[CapturedRequest]] = {}
        for req in requests:
            sid = getattr(req, "session_id", None) or getattr(req, "identity_id", None) or "unscoped"
            by_session.setdefault(str(sid), []).append(req)

        discovered: List[Workflow] = []
        for sid, reqs in by_session.items():
            # Order chronologically when a timestamp is available.
            reqs_sorted = sorted(reqs, key=lambda r: getattr(r, "timestamp", 0) or 0)
            if len(reqs_sorted) < 2:
                continue  # a single request is not a workflow
            wf = Workflow(
                name=f"workflow_{sid}",
                description=f"Observed request sequence for session {sid}",
                request_ids=[r.request_id for r in reqs_sorted],
            )
            self.add_workflow(wf)
            discovered.append(wf)
        return discovered
