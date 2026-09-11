import logging
from typing import Dict, Any, Tuple, List
from core.tools.models import ToolAttempt
from core.domain.finding import SecurityFinding

logger = logging.getLogger(__name__)

class BaseAdapter:
    def __init__(self, target: str, timeout: float = 900.0):
        self.target = target
        self.timeout = timeout
        self.tool_name = "base"

    def execute(self, args: Dict[str, Any]) -> Tuple[ToolAttempt, List[SecurityFinding]]:
        raise NotImplementedError()
