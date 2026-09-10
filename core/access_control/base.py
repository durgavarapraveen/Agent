import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AuthorizationOracle:
    @staticmethod
    def compare(baseline_status: int, test_status: int, baseline_body: str, test_body: str) -> str:
        if test_status == 401 or test_status == 403:
            return "REJECTED"
            
        if test_status == baseline_status and test_status < 400:
            # Do not treat HTTP 200 alone as proof. We must check evidence in the body.
            if test_body and baseline_body and len(test_body) > 10:
                # Basic heuristic: if the test body has meaningful content (not just "ok")
                # and matches the structure/size of the baseline, it's likely a real leak.
                if len(test_body) >= (len(baseline_body) * 0.5):
                    return "VULNERABLE"
            
            # If it's a 200 but the body is empty or drastically different (like a generic success or redirect),
            # it is just a candidate, not definitively proven.
            return "CANDIDATE"
            
        # Heuristic for partial access or different errors
        if test_status < 400:
            return "CANDIDATE"
            
        return "REJECTED"

class AccessControlTest:
    def __init__(self, replayer):
        self.replayer = replayer
        
    def execute(self, request_node, identities: Dict[str, Any]) -> Dict[str, str]:
        raise NotImplementedError()
