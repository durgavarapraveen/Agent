from core.access_control.base import AccessControlTest
from core.access_control.vertical import VerticalTest

class FunctionAccessTest(AccessControlTest):
    """
    Checks access to sensitive endpoints (e.g., /admin/settings).
    Effectively a wrapper/alias for Vertical Privilege Escalation.
    """
    def execute(self, request_node, identities) -> dict:
        # Delegate to VerticalTest
        return VerticalTest(self.replayer).execute(request_node, identities)
