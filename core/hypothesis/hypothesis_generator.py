import logging
import uuid
from typing import List, Optional
from core.coverage.coverage_engine import CoverageEngine
from core.attack_surface.graph import AttackSurfaceGraph
from core.domain.hypothesis import SecurityHypothesis
from core.domain.endpoint import Endpoint

logger = logging.getLogger(__name__)

ATTACK_TYPE_MAP = {
    "authentication": "credential_brute_force",
    "authorization": "idor",
    "sql_injection": "sql_injection",
    "input_validation": "sql_injection",
    "xss": "xss",
    "ssti": "ssti",
    "command_injection": "command_injection",
    "csrf": "csrf",
    "cors": "cors_misconfiguration",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "path_traversal": "path_traversal",
    "file_upload": "file_upload",
    "jwt": "jwt_manipulation",
    "graphql": "graphql_introspection",
    "api_security": "api_abuse",
    "business_logic": "business_logic_bypass",
    "race_condition": "race_condition",
    "secrets": "secret_exposure",
    "information_disclosure": "information_disclosure",
    "misconfiguration": "misconfiguration",
    "cryptography": "weak_crypto",
    "session": "session_hijacking",
    "identity": "identity_spoofing",
    "access_control": "privilege_escalation",
    "nosql_injection": "nosql_injection",
    "file_download": "arbitrary_file_read",
    "client_side": "dom_manipulation",
    "dependency": "dependency_vulnerability",
    "websocket": "websocket_hijacking",
}


class HypothesisGenerator:
    def __init__(self, coverage_engine: CoverageEngine, attack_surface: AttackSurfaceGraph):
        self.coverage_engine = coverage_engine
        self.attack_surface = attack_surface

    def generate(self, coverage_gaps: List[str], attack_surface: Optional[AttackSurfaceGraph] = None) -> List[SecurityHypothesis]:
        surface = attack_surface or self.attack_surface
        all_endpoints = surface.endpoints.get_endpoints()
        hypotheses = []

        for gap_test_id in coverage_gaps:
            test_def = self.coverage_engine.catalog.get_test(gap_test_id)
            if not test_def:
                logger.warning(f"No test definition for gap: {gap_test_id}")
                continue

            applicable_endpoints = self._find_applicable_endpoints(gap_test_id, all_endpoints)
            if not applicable_endpoints:
                applicable_endpoints = all_endpoints[:1] if all_endpoints else []

            for endpoint in applicable_endpoints:
                hypothesis = self._build_hypothesis(test_def, endpoint)
                hypotheses.append(hypothesis)

        logger.info(f"Generated {len(hypotheses)} hypotheses from {len(coverage_gaps)} coverage gaps")
        return hypotheses

    def _find_applicable_endpoints(self, test_id: str, all_endpoints: List[Endpoint]) -> List[Endpoint]:
        applicable = []
        endpoint_map = self.coverage_engine.state.endpoint_coverage_map
        for endpoint in all_endpoints:
            ep_tests = endpoint_map.get(endpoint.endpoint_id, {})
            if test_id in ep_tests:
                from core.domain.coverage import TestState
                status = ep_tests[test_id].status
                if status in {TestState.READY, TestState.NOT_TESTED, TestState.INCONCLUSIVE}:
                    applicable.append(endpoint)
        return applicable

    def _build_hypothesis(self, test_def, endpoint: Endpoint) -> SecurityHypothesis:
        attack_type = ATTACK_TYPE_MAP.get(test_def.category, test_def.category)
        expected_outcome = self._determine_expected_outcome(test_def, endpoint)

        params = endpoint.parameters
        param_names = [p.name for p in params] if params else []

        reasoning = (
            f"Coverage gap '{test_def.test_id}' on endpoint {endpoint.path} "
            f"({', '.join(endpoint.method_set)}). "
            f"Attack type: {attack_type}. "
            f"Parameters: {', '.join(param_names) if param_names else 'none'}. "
            f"Risk level: {test_def.risk_level}."
        )

        return SecurityHypothesis(
            id=str(uuid.uuid4()),
            source="hypothesis_generator",
            title=f"{attack_type} on {endpoint.path}",
            rationale=reasoning,
            expected_signals=list(test_def.required_evidence),
            test_id=test_def.test_id,
            endpoint_id=endpoint.endpoint_id,
            identity_ids=[ic.identity_id for ic in endpoint.auth_contexts],
            status="PROPOSED",
            confidence=self._base_confidence(test_def),
        )

    def _determine_expected_outcome(self, test_def, endpoint: Endpoint) -> str:
        if test_def.risk_level == "critical":
            return "vulnerability_likely"
        if endpoint.auth_required and test_def.category in ("authorization", "authentication", "session"):
            return "vulnerability_possible"
        return "needs_investigation"

    def _base_confidence(self, test_def) -> float:
        risk_scores = {"critical": 0.8, "high": 0.6, "medium": 0.4, "low": 0.2}
        return risk_scores.get(test_def.risk_level, 0.5)
