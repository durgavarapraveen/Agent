from core.access_control.base import AccessControlTest, AuthorizationOracle

class HorizontalTest(AccessControlTest):
    def execute(self, request_node, identities) -> dict:
        results = {}
        
        # We need at least two standard users
        standard_users = [uid for uid, iden in identities.items() if iden.role == "standard"]
        if len(standard_users) < 2:
            return results
            
        owner_id = standard_users[0]
        peer_id = standard_users[1]
        
        baseline_resp = self.replayer.replay(request_node, identity_id=owner_id)
        if not baseline_resp or baseline_resp["status"] >= 400:
            return results
            
        peer_resp = self.replayer.replay(request_node, identity_id=peer_id)
        
        result = AuthorizationOracle.compare(
            baseline_resp["status"], 
            peer_resp["status"], 
            baseline_resp["body"], 
            peer_resp["body"]
        )
        
        if result == "VULNERABLE":
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"PRIVILEGE_ESCALATION_CANDIDATE direction=horizontal identity={peer_id}")
            print(f"PRIVILEGE_ESCALATION_CANDIDATE direction=horizontal identity={peer_id}")
        
        results[peer_id] = result
        return results
