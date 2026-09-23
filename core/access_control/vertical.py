from core.access_control.base import AccessControlTest, AuthorizationOracle
from core.common import target_shape as ts

class VerticalTest(AccessControlTest):
    def execute(self, request_node, identities) -> dict:
        results = {}

        # Select by relative privilege: non-privileged authenticated users vs
        # privileged (admin) identities — not "standard"/"administrator" literals.
        standard_users = [uid for uid, iden in identities.items() if ts.role_rank(iden.role) == 1]
        admins = [uid for uid, iden in identities.items() if ts.is_admin_role(iden.role)]

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
