"""
Hypothesis Engine (Phase 22).

Generates testable hypotheses from the attack surface by analyzing:
- Discovered endpoints and parameters
- Detected technologies
- Prior experiment results (feedback loops)
- Coverage gaps

Each hypothesis maps to one or more SecurityTest entries and spawns experiments.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.attack_surface.attack_surface_state import AttackSurfaceState
    from core.coverage.security_test_catalog import SecurityTestCatalog
    from core.domain.hypothesis import SecurityHypothesis

logger = logging.getLogger(__name__)

TECH_ATTACK_MAP = {
    "php": ["cmdi_basic_01", "deser_php_01", "ssti_basic_01", "path_lfi_01"],
    "java": ["deser_java_01", "el_injection_01", "ssti_basic_01", "sqli_basic_01"],
    "python": ["deser_python_01", "ssti_jinja2_01", "ssti_basic_01", "cmdi_basic_01"],
    "node": ["ssti_basic_01", "nosqli_basic_01", "xss_dom_01", "cmdi_basic_01"],
    "express": ["ssti_basic_01", "nosqli_basic_01", "xss_dom_01"],
    "django": ["ssti_basic_01", "sqli_basic_01", "csrf_token_01"],
    "flask": ["ssti_jinja2_01", "sqli_basic_01", "cmdi_basic_01"],
    "spring": ["deser_java_01", "el_injection_01", "sqli_basic_01"],
    "rails": ["sqli_basic_01", "cmdi_basic_01", "csrf_token_01", "xss_reflected_01"],
    "wordpress": ["sqli_basic_01", "xss_stored_01", "path_traversal_01", "upload_type_01"],
    "nginx": ["path_traversal_01", "smuggle_clte_01", "header_injection_01"],
    "apache": ["path_traversal_01", "smuggle_clte_01", "config_tls_01"],
    "graphql": ["api_graphql_introspection_01", "api_graphql_dos_01",
                "api_graphql_mutation_01", "api_graphql_batching_01"],
    "mongodb": ["nosqli_basic_01", "nosqli_logical_01", "nosqli_js_01"],
    "jwt": ["jwt_manipulation_01", "jwt_algo_confusion_01", "jwt_none_algo_01"],
    "react": ["xss_dom_01", "client_dom_sink_01", "client_postmessage_01"],
    "angular": ["xss_dom_01", "client_dom_sink_01", "ssti_basic_01"],
    "vue": ["xss_dom_01", "client_dom_sink_01", "ssti_basic_01"],
}

PARAM_TYPE_TESTS = {
    "id": ["authz_idor_01", "authz_object_level_01", "sqli_basic_01"],
    "url": ["ssrf_basic_01", "open_redirect_01", "ssrf_cloud_01"],
    "file": ["path_traversal_01", "path_lfi_01", "upload_type_01"],
    "path": ["path_traversal_01", "path_lfi_01"],
    "search": ["xss_reflected_01", "sqli_basic_01", "ssti_basic_01"],
    "query": ["sqli_basic_01", "xss_reflected_01"],
    "redirect": ["open_redirect_01"],
    "callback": ["open_redirect_01", "ssrf_basic_01"],
    "email": ["sqli_basic_01", "xss_reflected_01"],
    "username": ["sqli_basic_01", "auth_username_enum_01"],
    "password": ["auth_password_policy_01"],
    "token": ["jwt_manipulation_01", "auth_session_hijack_01"],
    "page": ["sqli_basic_01", "path_traversal_01"],
    "sort": ["sqli_basic_01"],
    "order": ["sqli_basic_01"],
    "filter": ["sqli_basic_01", "nosqli_basic_01"],
    "xml": ["xxe_basic_01"],
    "data": ["xss_stored_01", "sqli_basic_01"],
    "cmd": ["cmdi_basic_01"],
    "exec": ["cmdi_basic_01"],
    "command": ["cmdi_basic_01"],
    "template": ["ssti_basic_01"],
    "lang": ["path_traversal_01"],
    "locale": ["path_traversal_01"],
}


class HypothesisEngine:

    def __init__(self, catalog: SecurityTestCatalog):
        self._catalog = catalog
        self._generated: List[Dict[str, Any]] = []
        self._feedback: Dict[str, Dict[str, Any]] = {}

    def generate_from_surface(
        self,
        surface: AttackSurfaceState,
    ) -> List[Dict[str, Any]]:
        hypotheses: List[Dict[str, Any]] = []

        hypotheses.extend(self._from_technologies(surface))
        hypotheses.extend(self._from_parameters(surface))
        hypotheses.extend(self._from_endpoints(surface))
        hypotheses.extend(self._baseline_hypotheses(surface))

        hypotheses = self._deduplicate(hypotheses)
        hypotheses = self._prioritize(hypotheses)

        self._generated = hypotheses
        logger.info(f"HYPOTHESIS_ENGINE generated={len(hypotheses)} "
                    f"from tech={len(surface.technologies)} "
                    f"endpoints={len(surface.endpoints)} "
                    f"params={len(surface.parameters)}")
        return hypotheses

    def record_feedback(self, test_id: str, endpoint_id: str,
                        outcome: str, details: Dict[str, Any] = None) -> None:
        key = f"{test_id}:{endpoint_id}"
        self._feedback[key] = {
            "outcome": outcome,
            "details": details or {},
        }

    def suggest_follow_ups(self, test_id: str, endpoint_id: str,
                           outcome: str) -> List[str]:
        follow_ups = []
        if outcome == "CONFIRMED":
            if "sqli" in test_id:
                follow_ups.extend(["sqli_time_based_01", "sqli_union_01",
                                   "sqli_stacked_01"])
            elif "xss" in test_id:
                follow_ups.extend(["xss_stored_01", "xss_dom_01",
                                   "xss_mutation_01"])
            elif "cmdi" in test_id:
                follow_ups.extend(["cmdi_blind_01", "cmdi_dns_01"])
            elif "ssrf" in test_id:
                follow_ups.extend(["ssrf_cloud_01", "ssrf_redirect_01"])
            elif "ssti" in test_id:
                follow_ups.extend(["ssti_jinja2_01", "ssti_freemarker_01"])
        elif outcome == "INCONCLUSIVE":
            if "sqli" in test_id:
                follow_ups.extend(["sqli_time_based_01", "sqli_error_based_01"])
            elif "xss" in test_id:
                follow_ups.extend(["xss_encoded_01", "xss_dom_01"])
            elif "cmdi" in test_id:
                follow_ups.extend(["cmdi_blind_01"])
        return [f for f in follow_ups if f != test_id]

    def _from_technologies(self, surface: AttackSurfaceState) -> List[Dict[str, Any]]:
        results = []
        for tech_name, tech_data in surface.technologies.items():
            key = tech_name.lower().split("/")[0].split(" ")[0]
            test_ids = TECH_ATTACK_MAP.get(key, [])
            for test_id in test_ids:
                test = self._catalog.get(test_id)
                if not test:
                    continue
                results.append({
                    "id": str(uuid.uuid4()),
                    "title": f"{test.name} ({tech_name})",
                    "rationale": f"Technology {tech_name} detected — {test.description}",
                    "test_id": test_id,
                    "attack_type": test.attack_type,
                    "technology_hint": tech_name,
                    "priority": 0.7,
                    "generation_method": "technology_mapping",
                })
        return results

    def _from_parameters(self, surface: AttackSurfaceState) -> List[Dict[str, Any]]:
        results = []
        for param_key, param_data in surface.parameters.items():
            name = param_data.get("name", param_key.split(":")[-1]).lower()
            for hint, test_ids in PARAM_TYPE_TESTS.items():
                if hint in name:
                    for test_id in test_ids:
                        test = self._catalog.get(test_id)
                        if not test:
                            continue
                        results.append({
                            "id": str(uuid.uuid4()),
                            "title": f"{test.name} on param '{name}'",
                            "rationale": f"Parameter name '{name}' suggests {test.attack_type}",
                            "test_id": test_id,
                            "attack_type": test.attack_type,
                            "endpoint_id": param_data.get("endpoint_id"),
                            "parameter_name": name,
                            "priority": 0.6,
                            "generation_method": "parameter_naming",
                        })
                    break
        return results

    def _from_endpoints(self, surface: AttackSurfaceState) -> List[Dict[str, Any]]:
        results = []
        for ep_key, ep_data in surface.endpoints.items():
            methods = ep_data.get("methods", [])
            path = ep_data.get("path", ep_key)

            if any(m in ("POST", "PUT", "PATCH", "DELETE") for m in methods):
                results.append({
                    "id": str(uuid.uuid4()),
                    "title": f"CSRF on {path}",
                    "rationale": f"State-changing endpoint {path}",
                    "test_id": "csrf_token_01",
                    "attack_type": "csrf",
                    "endpoint_id": ep_key,
                    "priority": 0.5,
                    "generation_method": "endpoint_method",
                })

            if "/api/" in path or "/rest/" in path or "/v1/" in path:
                for tid in ["api_excessive_data_01", "api_rate_limit_01",
                            "authz_mass_assignment_01"]:
                    test = self._catalog.get(tid)
                    if test:
                        results.append({
                            "id": str(uuid.uuid4()),
                            "title": f"{test.name} on {path}",
                            "rationale": f"API endpoint {path}",
                            "test_id": tid,
                            "attack_type": test.attack_type,
                            "endpoint_id": ep_key,
                            "priority": 0.6,
                            "generation_method": "endpoint_pattern",
                        })

            if "{" in path:
                for tid in ["authz_idor_01", "authz_object_level_01"]:
                    test = self._catalog.get(tid)
                    if test:
                        results.append({
                            "id": str(uuid.uuid4()),
                            "title": f"{test.name} on {path}",
                            "rationale": f"Path contains object ID placeholder",
                            "test_id": tid,
                            "attack_type": test.attack_type,
                            "endpoint_id": ep_key,
                            "priority": 0.8,
                            "generation_method": "endpoint_pattern",
                        })
        return results

    def _baseline_hypotheses(self, surface: AttackSurfaceState) -> List[Dict[str, Any]]:
        results = []
        baseline_tests = [
            "cors_misconfig_01", "config_hsts_01", "config_xframe_01",
            "config_csp_01", "info_version_header_01", "path_sensitive_files_01",
            "path_backup_files_01", "info_debug_endpoint_01",
            "dns_takeover_01", "config_tls_01",
        ]
        for tid in baseline_tests:
            test = self._catalog.get(tid)
            if test:
                results.append({
                    "id": str(uuid.uuid4()),
                    "title": test.name,
                    "rationale": test.description,
                    "test_id": tid,
                    "attack_type": test.attack_type,
                    "priority": 0.4,
                    "generation_method": "baseline",
                })
        return results

    def _deduplicate(self, hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for h in hypotheses:
            key = (h.get("test_id", ""), h.get("endpoint_id", ""),
                   h.get("parameter_name", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        return deduped

    def _prioritize(self, hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for h in hypotheses:
            key = f"{h.get('test_id', '')}:{h.get('endpoint_id', '')}"
            fb = self._feedback.get(key)
            if fb:
                if fb["outcome"] == "CONFIRMED":
                    h["priority"] = min(1.0, h.get("priority", 0.5) + 0.2)
                elif fb["outcome"] == "REJECTED":
                    h["priority"] = max(0.1, h.get("priority", 0.5) - 0.3)
        return sorted(hypotheses, key=lambda h: h.get("priority", 0.5), reverse=True)
