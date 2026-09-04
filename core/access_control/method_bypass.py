from core.access_control.base import AccessControlTest, AuthorizationOracle
import copy

class MethodBypassTest(AccessControlTest):
    """
    Mutates HTTP methods (e.g. GET to POST/PUT) to test for flawed routing authorization.
    """
    def execute(self, request_node, identities) -> dict:
        results = {}
        
        # We need a standard user to test method bypass
        standard_users = [uid for uid, iden in identities.items() if iden.role == "standard"]
        if not standard_users:
            return results
            
        owner_id = standard_users[0]
        
        baseline_resp = self.replayer.replay(request_node, identity_id=owner_id)
        if not baseline_resp or baseline_resp["status"] >= 400:
            return results
            
        original_method = request_node.get("method", "GET").upper()
        mutated_methods = ["POST", "PUT", "DELETE", "PATCH"] if original_method == "GET" else ["GET"]
        
        for method in mutated_methods:
            mutated_request = copy.deepcopy(request_node)
            mutated_request["method"] = method
            
            mutated_resp = self.replayer.replay(mutated_request, identity_id=owner_id)
            
            # If the mutated method works (returns a 200/similar to baseline) when it maybe shouldn't, flag it.
            # However, for method bypass, comparing to baseline GET is tricky because POST might naturally return 201 or 400.
            # But we follow the Oracle pattern for simplicity.
            result = AuthorizationOracle.compare(
                baseline_resp["status"], 
                mutated_resp["status"], 
                baseline_resp["body"], 
                mutated_resp["body"]
            )
            results[f"METHOD_BYPASS_{method}"] = result
            
        return results
