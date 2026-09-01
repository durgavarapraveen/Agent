import logging
from typing import Dict, Any, List
from core.coverage.test_definition import SecurityTestDefinition
from core.memory.shared_context_v2 import SharedContextV2

logger = logging.getLogger(__name__)

class ApplicabilityEngine:
    """Evaluates applicability rules against the SharedContext."""

    def __init__(self, shared_context: SharedContextV2):
        self.shared_context = shared_context

    def is_applicable(self, test: SecurityTestDefinition) -> bool:
        """Evaluate if a test is applicable based on its rules and current context."""
        if not test.applicability_rules:
            return True

        for rule in test.applicability_rules:
            rule_type = rule.get("rule_type")
            
            if rule_type == "always_applicable":
                continue
                
            if rule_type == "requires_technology":
                tech = rule.get("technology")
                # Evaluate against shared context technologies
                tech_found = False
                for host, techs in self.shared_context.technologies.items():
                    if tech in techs:
                        tech_found = True
                        break
                if not tech_found:
                    logger.debug(f"Test {test.test_id} not applicable: requires {tech}")
                    return False
                    
            if rule_type == "requires_auth":
                if not self.shared_context.identities:
                    logger.debug(f"Test {test.test_id} not applicable: requires auth")
                    return False

            # Add more rule evaluations as needed
            
        return True
