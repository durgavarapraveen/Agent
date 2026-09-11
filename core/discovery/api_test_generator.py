"""Phase 4.1 — API-first deep testing: extra importers + test-spec generation.

``APISchemaImporter`` already imports OpenAPI 3.x / Swagger 2.0 / GraphQL
introspection into endpoint dicts. This module adds the two missing import
formats (Postman collections, gRPC ``.proto`` files) and — the main value — an
auto-generator that turns imported endpoints into executable API test specs:

  * mass assignment — send privileged fields not in the schema;
  * broken function-level auth (BFLA) — call privileged endpoints as a low role;
  * excessive data exposure — flag response fields not documented in the schema;
  * parameter pollution — duplicate params / array-inject scalar fields.

Endpoint dicts follow the importer's shape ({url, method, path, params, ...}).
Everything here is pure and unit-testable — no network, no live API.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Fields attackers try to smuggle via mass assignment.
MASS_ASSIGNMENT_FIELDS = ["is_admin", "isAdmin", "role", "roles", "admin",
                          "verified", "is_verified", "account_balance", "balance",
                          "credit", "user_id", "owner_id", "price", "status"]

_PRIVILEGED_HINTS = ("/admin", "/internal", "/manage", "delete", "/users", "/roles",
                     "/config", "/settings", "/billing")


# ── Extra importers ──────────────────────────────────────────────────────────
def parse_postman_collection(collection: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a Postman v2.1 collection into endpoint dicts."""
    endpoints: List[Dict[str, Any]] = []

    def _walk(items: List[Dict[str, Any]]):
        for item in items or []:
            if "item" in item:               # folder
                _walk(item["item"])
                continue
            req = item.get("request")
            if not req:
                continue
            method = (req.get("method") or "GET").upper()
            url = req.get("url")
            if isinstance(url, dict):
                url = url.get("raw", "")
            url = url or ""
            params = []
            body = req.get("body", {}) or {}
            raw = body.get("raw", "")
            if raw:
                params = _field_names_from_body(raw)
            q = urlparse(url).query
            params += [kv.split("=")[0] for kv in q.split("&") if kv]
            endpoints.append({
                "url": url, "method": method, "path": urlparse(url).path or url,
                "params": sorted(set(p for p in params if p)),
                "source": "postman", "name": item.get("name", ""),
            })

    _walk(collection.get("item", []))
    return endpoints


def parse_grpc_proto(proto_text: str) -> List[Dict[str, Any]]:
    """Extract gRPC service methods from a .proto file as endpoint dicts.
    Each rpc becomes POST /<Service>/<Method> (gRPC-over-HTTP convention)."""
    endpoints: List[Dict[str, Any]] = []
    # Match: service Foo { rpc Bar (Req) returns (Resp); ... }
    for svc in re.finditer(r"service\s+(\w+)\s*\{([^}]*)\}", proto_text, re.DOTALL):
        service, body = svc.group(1), svc.group(2)
        for rpc in re.finditer(r"rpc\s+(\w+)\s*\(\s*(?:stream\s+)?(\w+)\s*\)\s*"
                               r"returns\s*\(\s*(?:stream\s+)?(\w+)\s*\)", body):
            method_name, req_type, resp_type = rpc.group(1), rpc.group(2), rpc.group(3)
            endpoints.append({
                "url": f"/{service}/{method_name}", "method": "POST",
                "path": f"/{service}/{method_name}", "params": [],
                "source": "grpc", "request_type": req_type, "response_type": resp_type,
            })
    return endpoints


def _field_names_from_body(raw: str) -> List[str]:
    try:
        import json
        data = json.loads(raw)
        if isinstance(data, dict):
            return list(data.keys())
    except (ValueError, TypeError):
        pass
    return []


# ── Test-spec generation ─────────────────────────────────────────────────────
def _param_names(ep: Dict[str, Any]) -> List[str]:
    p = ep.get("params")
    if isinstance(p, dict):
        return list(p.keys())
    if isinstance(p, (list, tuple)):
        return [x.get("name", str(x)) if isinstance(x, dict) else str(x) for x in p]
    if isinstance(p, str):
        return [s.strip() for s in p.replace("&", ",").split(",") if s.strip()]
    return []


def _is_privileged(ep: Dict[str, Any]) -> bool:
    u = (ep.get("url", "") + " " + ep.get("path", "")).lower()
    return any(h in u for h in _PRIVILEGED_HINTS)


def _has_body(ep: Dict[str, Any]) -> bool:
    return (ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")) or bool(_param_names(ep))


class APITestGenerator:

    def generate(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        specs: List[Dict[str, Any]] = []
        for ep in endpoints:
            specs.extend(self._for_endpoint(ep))
        return specs

    def _for_endpoint(self, ep: Dict[str, Any]) -> List[Dict[str, Any]]:
        specs: List[Dict[str, Any]] = []
        url = ep.get("url", "") or ep.get("path", "")
        method = ep.get("method", "GET").upper()
        params = _param_names(ep)

        # Mass assignment — endpoints that accept a body.
        if _has_body(ep):
            specs.append(self._spec("mass_assignment", "authorization", ep,
                                    mutation={"extra_fields": MASS_ASSIGNMENT_FIELDS},
                                    rationale="Send privileged fields not in the schema; "
                                              "check if they persist."))

        # Broken function-level auth — privileged endpoints called as a low role.
        if _is_privileged(ep):
            specs.append(self._spec("broken_function_level_auth", "role_escalation", ep,
                                    mutation={"identity": "low_privilege"},
                                    rationale="Call a privileged endpoint with a user-level token."))

        # Excessive data exposure — GET responses vs documented schema.
        if method == "GET" and (ep.get("response_schema") or ep.get("response_fields")):
            documented = ep.get("response_fields") or list(
                (ep.get("response_schema") or {}).keys())
            specs.append(self._spec("excessive_data_exposure", "authorization", ep,
                                    mutation={"documented_fields": documented},
                                    rationale="Flag response fields not present in the schema."))

        # Parameter pollution — any endpoint with params.
        if params:
            specs.append(self._spec("parameter_pollution", "business_logic", ep,
                                    mutation={"duplicate_params": params,
                                              "array_inject": params},
                                    rationale="Duplicate params / array-inject scalar fields."))
        return specs

    @staticmethod
    def _spec(technique: str, capability: str, ep: Dict[str, Any],
              mutation: Dict[str, Any], rationale: str) -> Dict[str, Any]:
        return {
            "technique": technique,
            "capability": capability,
            "url": ep.get("url", "") or ep.get("path", ""),
            "method": ep.get("method", "GET").upper(),
            "params": _param_names(ep),
            "mutation": mutation,
            "rationale": rationale,
            "source": ep.get("source", "api"),
            "priority": "high" if technique in ("mass_assignment", "broken_function_level_auth")
                        else "medium",
        }

    def from_importer(self, importer: Any) -> List[Dict[str, Any]]:
        """Generate specs from an APISchemaImporter instance (reuse)."""
        try:
            endpoints = importer.import_all()
        except Exception as e:
            logger.warning("api_test_generator: importer.import_all failed (%s)", e)
            return []
        return self.generate(endpoints or [])
