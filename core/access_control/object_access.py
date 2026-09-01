from core.access_control.base import AccessControlTest
from core.access_control.horizontal import HorizontalTest

class ObjectAccessTest(AccessControlTest):
    """
    Checks if users can access underlying objects belonging to others.
    Effectively a wrapper/alias for Horizontal Privilege Escalation in our matrix.
    """
    def execute(self, request_node, identities) -> dict:
        # Delegate to HorizontalTest
        return HorizontalTest(self.replayer).execute(request_node, identities)
