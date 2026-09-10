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
        if not requests:
            return []

        # Bucket requests by their real session identifier.
        by_session: Dict[str, List[CapturedRequest]] = {}
        for req in requests:
            sid = getattr(req, "session_id", None) or getattr(req, "identity_id", None) or "unscoped"
            by_session.setdefault(str(sid), []).append(req)

        discovered: List[Workflow] = []
        for sid, reqs in by_session.items():
            # Order chronologically. Requests missing a timestamp are appended
            # in insertion order AFTER the sorted ones — previously
            # `getattr(req, "timestamp", 0) or 0` collapsed them to 0 which
            # silently placed them at the head of the workflow and misordered
            # every downstream analysis (#144).
            def _ts_key(r):
                ts = getattr(r, "timestamp", None)
                # Use +inf so missing timestamps sort last, preserving order.
                return (0, ts) if ts not in (None, "") else (1, float("inf"))
            reqs_sorted = sorted(reqs, key=_ts_key)
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
