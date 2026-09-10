from core.access_control.base import AccessControlTest, AuthorizationOracle
import copy
import re

class IdorTest(AccessControlTest):
    def execute(self, request_node, identities) -> dict:
        results = {}
        
        # We need a standard user to test IDOR
        standard_users = [uid for uid, iden in identities.items() if iden.role == "standard"]
        if not standard_users:
            return results
            
        owner_id = standard_users[0]
        
        # Determine if the request has an obvious ID to mutate
        path = request_node.get("path", "")
        
        # We explicitly target paths that hint at object, account, user, order, basket, document, or resource identifiers.
        # This is a basic heuristic matching common REST patterns like /api/users/123 or /orders/456
        target_resources = r'(object|account|user|order|basket|document|resource)s?'
        match = re.search(fr'/{target_resources}/([^/]+)(/|$)', path, re.IGNORECASE)
        
        if not match:
            # Fallback to generic ID at the end of path
            match = re.search(r'/(\d+)$', path)
            if not match:
                return results
                
            original_id = match.group(1)
            mutated_id = str(int(original_id) + 1)
            mutated_path = path[:match.start(1)] + mutated_id
        else:
            original_id = match.group(2)
            # Try to mutate if it's numeric, otherwise just append a string
            if original_id.isdigit():
                mutated_id = str(int(original_id) + 1)
            else:
                mutated_id = original_id + "-mutated"
            mutated_path = path[:match.start(2)] + mutated_id + path[match.end(2):]
        
        baseline_resp = self.replayer.replay(request_node, identity_id=owner_id)
        if not baseline_resp or baseline_resp["status"] >= 400:
            return results
            
        # Mutate the request
        mutated_request = copy.deepcopy(request_node)
        mutated_request["path"] = mutated_path
        
        mutated_resp = self.replayer.replay(mutated_request, identity_id=owner_id)
        
        result = AuthorizationOracle.compare(
            baseline_resp["status"], 
            mutated_resp["status"], 
            baseline_resp["body"], 
            mutated_resp["body"]
        )
        
        results["IDOR"] = result
        return results
