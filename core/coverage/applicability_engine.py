from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.coverage.security_test_catalog import SecurityTest, SecurityTestCatalog


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
