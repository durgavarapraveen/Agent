from core.access_control.base import AccessControlTest, AuthorizationOracle
import logging

logger = logging.getLogger(__name__)

class UnauthenticatedTest(AccessControlTest):
    """
    Strips session artifacts to test for unauthenticated access.
    """
    def execute(self, request_node, identities) -> dict:
        results = {}
        
        # We need a baseline to compare against. Assume the first identity is the baseline owner.
        if not identities:
            return results
            
        owner_id = list(identities.keys())[0]
        
        baseline_resp = self.replayer.replay(request_node, identity_id=owner_id)
        if not baseline_resp or baseline_resp["status"] >= 400:
            return results # Can't test if baseline fails
            
        anon_resp = self.replayer.replay(request_node, identity_id=None) # Anonymous
        
        result = AuthorizationOracle.compare(
            baseline_resp["status"], 
            anon_resp["status"], 
            baseline_resp["body"], 
            anon_resp["body"]
        )
        
        results["anonymous"] = result
        return results
