import logging
from core.access_control.unauthenticated import UnauthenticatedTest
from core.access_control.horizontal import HorizontalTest
from core.access_control.vertical import VerticalTest
from core.access_control.idor import IdorTest

logger = logging.getLogger(__name__)

class MatrixEngine:
    def __init__(self, replayer, identities, shared_context=None):
        self.replayer = replayer
        self.identities = identities
        self.shared_context = shared_context
        
        # Instantiate test engines
        self.tests = [
            UnauthenticatedTest(replayer),
            HorizontalTest(replayer),
            VerticalTest(replayer),
            IdorTest(replayer)
        ]
        
    def analyze(self, request_node):
        path = request_node.get("path", "unknown")
        logger.info(f"AUTHORIZATION_TEST_STARTED endpoint={path}")
        print(f"AUTHORIZATION_TEST_STARTED endpoint={path}")
        
        matrix_results = {}
        idor_result = "REJECTED"
        
        # 1. Baseline - get the status of the owner (assume standard user 0 is owner)
        standard_users = [uid for uid, iden in self.identities.items() if iden.role == "standard"]
        if not standard_users:
            return
            
        owner_id = standard_users[0]
        baseline_resp = self.replayer.replay(request_node, identity_id=owner_id)
        if baseline_resp:
            matrix_results[owner_id] = baseline_resp["status"]
        
        # Run all tests
        for test in self.tests:
            results = test.execute(request_node, self.identities)
            
            # Map results to matrix
            if isinstance(test, UnauthenticatedTest):
                # UnauthenticatedTest returns {"anonymous": "VULNERABLE"/"REJECTED"}
                # We want to map this to an HTTP status in the matrix for the required output format.
                anon_resp = self.replayer.replay(request_node, identity_id=None)
                matrix_results["anonymous"] = anon_resp["status"] if anon_resp else 0
                
            elif isinstance(test, HorizontalTest):
                for peer_id, result in results.items():
                    peer_resp = self.replayer.replay(request_node, identity_id=peer_id)
                    matrix_results[peer_id] = peer_resp["status"] if peer_resp else 0
                    
            elif isinstance(test, VerticalTest):
                for admin_id, result in results.items():
                    # For vertical, we might need to know the admin's actual response status
                    admins = [uid for uid, iden in self.identities.items() if iden.role == "administrator"]
                    if admins:
                        admin_resp = self.replayer.replay(request_node, identity_id=admins[0])
                        matrix_results[admins[0]] = admin_resp["status"] if admin_resp else 0
                        
            elif isinstance(test, IdorTest):
                if "IDOR" in results:
                    idor_result = results["IDOR"]
                    if idor_result == "VULNERABLE":
                        logger.warning(f"IDOR_VALIDATED cross_user_access=true")
                        print(f"IDOR_VALIDATED\ncross_user_access=true")
                    elif idor_result == "CANDIDATE":
                        logger.warning(f"IDOR_CANDIDATE cross_user_access=true")
                        print(f"IDOR_CANDIDATE\ncross_user_access=true")
                        
        self._emit_matrix(path, matrix_results, idor_result)
        
        logger.info(f"AUTHORIZATION_TEST_COMPLETED endpoint={path}")
        print(f"AUTHORIZATION_TEST_COMPLETED endpoint={path}")
        
        # Write to shared context
        if self.shared_context:
            with self.shared_context._state_lock:
                if not hasattr(self.shared_context, "authorization_coverage"):
                    self.shared_context.authorization_coverage = {}
                self.shared_context.authorization_coverage[path] = {
                    "matrix": matrix_results,
                    "idor": idor_result
                }
        
    def _emit_matrix(self, endpoint, results, idor_result):
        logger.info("AUTHORIZATION_MATRIX_CREATED")
        print("AUTHORIZATION_MATRIX_CREATED")
        
        output = [
            "AUTHORIZATION_MATRIX",
            f"endpoint={endpoint}",
            ""
        ]
        
        for identity, status in results.items():
            output.append(f"{identity}={status}")
            
        output.append("")
        output.append(f"IDOR={idor_result}")
        
        matrix_str = "\n".join(output)
        logger.info("\n" + matrix_str)
        print(matrix_str)
