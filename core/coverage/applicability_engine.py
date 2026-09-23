from __future__ import annotations

import os
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.coverage.security_test_catalog import SecurityTest, SecurityTestCatalog


class ApplicabilityResult(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    NOT_DISCOVERED = "not_discovered"


class ApplicabilityEngine:

    def __init__(self, test_catalog: SecurityTestCatalog, attack_surface: Any = None) -> None:
        self.catalog = test_catalog
        self.attack_surface = attack_surface

    def is_applicable(
        self,
        test: SecurityTest,
        endpoint: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        identities: Optional[List[str]] = None,
    ) -> bool:
        kw = {
            "path": endpoint.get("path", endpoint.get("url", "")),
            "parameters": parameters or endpoint.get("parameters", []),
            "identities": identities or [],
            "auth_required": endpoint.get("auth_required", False),
            "content_type": endpoint.get("content_type", "text/html"),
            "has_jwt": endpoint.get("has_jwt", False),
        }
        return test.applicable_to(**kw)

    def classify_applicability(
        self,
        test: SecurityTest,
        endpoint: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        identities: Optional[List[str]] = None,
        discovered_features: Optional[Dict[str, bool]] = None,
    ) -> Tuple[ApplicabilityResult, str]:
        features = discovered_features or {}

        feature_requirements = {
            "has_jwt": test.attack_type in ("jwt",),
            "has_graphql": test.attack_type in ("graphql",),
            "has_websocket": test.attack_type in ("websocket",),
            "has_login": test.attack_type in ("authentication",) and any(
                p in test.test_id for p in ("login", "password", "credential", "lockout", "otp", "mfa")
            ),
            "has_otp": "otp" in test.test_id or "mfa" in test.test_id,
        }

        for feature_key, required in feature_requirements.items():
            if not required:
                continue
            if feature_key not in features:
                return ApplicabilityResult.NOT_DISCOVERED, f"Feature '{feature_key}' not yet probed by recon"
            if not features[feature_key]:
                return ApplicabilityResult.NOT_APPLICABLE, f"Feature '{feature_key}' confirmed absent"

        # Generic surface gate (env COVERAGE_STRICT_APPLICABILITY, default on):
        # a test whose attack class needs an INPUT to exercise (injection/xss/…)
        # is genuinely NOT_APPLICABLE to a GET/HEAD endpoint that exposes no
        # parameters and no query — there is nothing to inject into. This stops
        # every input-dependent test counting as "applicable" on every static
        # endpoint (the ~235-tests-×-every-endpoint denominator explosion that
        # pinned coverage near 0%). It only ever marks a cell NOT_APPLICABLE when
        # there is provably no input surface, so it does not hide a real gap.
        # Body-bearing methods (POST/PUT/PATCH/DELETE) are always kept.
        if os.getenv("COVERAGE_STRICT_APPLICABILITY", "1").strip().lower() in ("1", "true", "yes", "on"):
            _INPUT_DEPENDENT = {
                "injection", "sql_injection", "sqli", "nosql", "nosql_injection",
                "xss", "ssti", "command_injection", "cmdi", "xxe", "open_redirect",
                "path_traversal", "lfi", "rfi", "ssrf", "ldap", "xpath",
            }
            at = (test.attack_type or "").lower()
            method = (endpoint.get("method") or "GET").upper()
            params = parameters or endpoint.get("parameters", [])
            url = endpoint.get("url", "") or endpoint.get("path", "")
            has_query = "?" in url and "=" in url.split("?", 1)[1]
            if at in _INPUT_DEPENDENT and method in ("GET", "HEAD") \
                    and not params and not has_query:
                return ApplicabilityResult.NOT_APPLICABLE, \
                    "no input surface (no params/query on a GET) for input-dependent test"

        if self.is_applicable(test, endpoint, parameters, identities):
            return ApplicabilityResult.APPLICABLE, ""
        return ApplicabilityResult.NOT_APPLICABLE, "Predicate returned False"

    def get_applicable_tests(
        self,
        endpoint: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        identities: Optional[List[str]] = None,
    ) -> List[SecurityTest]:
        result = []
        for test in self.catalog.list_all():
            if self.is_applicable(test, endpoint, parameters, identities):
                result.append(test)
        return result

    def classify_all_tests(
        self,
        endpoint: Dict[str, Any],
        parameters: Optional[List[Dict[str, Any]]] = None,
        identities: Optional[List[str]] = None,
        discovered_features: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, List[SecurityTest]]:
        result: Dict[str, List[SecurityTest]] = {
            "applicable": [],
            "not_applicable": [],
            "not_discovered": [],
        }
        for test in self.catalog.list_all():
            status, _ = self.classify_applicability(test, endpoint, parameters, identities, discovered_features)
            result[status.value].append(test)
        return result
