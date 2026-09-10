from core.access_control.base import AccessControlTest, AuthorizationOracle

class VerticalTest(AccessControlTest):
    def execute(self, request_node, identities) -> dict:
        results = {}
        
        standard_users = [uid for uid, iden in identities.items() if iden.role == "standard"]
        admins = [uid for uid, iden in identities.items() if iden.role == "administrator"]
        
        if not standard_users or not admins:
            return results
            
        standard_id = standard_users[0]
        admin_id = admins[0]
        
        # In vertical testing, we assume the baseline owner is the admin (since we are testing access to admin endpoints)
        # If the endpoint doesn't actually belong to the admin, this test's results are not meaningful for Vertical Esc.
        baseline_resp = self.replayer.replay(request_node, identity_id=admin_id)
        if not baseline_resp or baseline_resp["status"] >= 400:
            return results
            
        standard_resp = self.replayer.replay(request_node, identity_id=standard_id)
        
        result = AuthorizationOracle.compare(
            baseline_resp["status"], 
            standard_resp["status"], 
            baseline_resp["body"], 
            standard_resp["body"]
        )
        
        if result == "VULNERABLE":
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"PRIVILEGE_ESCALATION_CANDIDATE direction=vertical identity={standard_id}")
            print(f"PRIVILEGE_ESCALATION_CANDIDATE direction=vertical identity={standard_id}")
        
        results[standard_id] = result
        return results
