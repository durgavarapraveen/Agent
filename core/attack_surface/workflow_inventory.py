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
        Simplified heuristic: Groups sequential requests by the same session_id 
        if they occur within a short timeframe (mocking this logic for now).
        Returns a list of extracted Workflows.
        """
        # For this prototype implementation, we'll just mock discovery
        # A real implementation would chronologically sort requests per session
        # and slice them based on time gaps or clear logic sequences.
        mock_workflow = Workflow(
            name=f"discovered_workflow_{uuid.uuid4().hex[:8]}",
            description="Auto-discovered workflow from sequential session requests",
            request_ids=[req.request_id for req in requests[:5]] # Grabbing first 5 as a mock sequence
        )
        self.add_workflow(mock_workflow)
        return [mock_workflow]
