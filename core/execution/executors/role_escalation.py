"""Phase 1.4 — role escalation & object-level authorization sequence finder.

``MatrixEngine`` (core.access_control) already runs per-endpoint identity
matrices (horizontal / vertical / IDOR / unauthenticated). This module adds the
*sequence* dimension human pentesters rely on for BOLA / broken object-level
authorization:

  * create a resource as user A, then read / update / delete it as user B or
    unauthenticated — every cross-actor access should be rejected;
  * object-level auth: is the check done only at creation, or on every access?
  * vertical escalation: a low-privilege identity hitting admin endpoints.

The analyzer is pure — it drives an injected ``replay(request, identity_id)``
callable — so it unit-tests against a mock app (secure vs. vulnerable) with no
live target. ``RoleEscalationExecutor`` binds it to ``GenericHTTPExecutor._probe``
with per-identity auth headers at runtime.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus
from core.execution.executors.generic import GenericHTTPExecutor
from core.exploitation.workflow_interceptor import SUCCESS_STATUSES, ReplayResponse

logger = logging.getLogger(__name__)

# replay(request_dict, identity_id_or_None) -> ReplayResponse
Replay = Callable[[Dict[str, Any], Optional[str]], ReplayResponse]

ADMIN_ROLES = frozenset({"admin", "administrator", "superuser", "root", "staff"})


@dataclass
class ResourceCrud:
    """CRUD request templates for one resource type. Each op is a request dict
    {method,url,headers,post_data} or None if not applicable."""
    name: str
    create: Optional[Dict[str, Any]] = None
    read: Optional[Dict[str, Any]] = None
    update: Optional[Dict[str, Any]] = None
    delete: Optional[Dict[str, Any]] = None


@dataclass
class EscalationFinding:
    test: str                    # bola | auth_bypass | vertical_escalation
    scenario: str
    resource: str
    operation: str
    actor: Optional[str]
    victim: str
    status: int
    severity: str

    def to_dict(self) -> Dict[str, Any]:
        return {"test": self.test, "scenario": self.scenario,
                "resource": self.resource, "operation": self.operation,
                "actor": self.actor, "victim": self.victim,
                "status": self.status, "severity": self.severity}


class RoleEscalationAnalyzer:

    def __init__(self, replay: Replay, identities: Dict[str, str]):
        """identities: {identity_id: role}. Roles in ADMIN_ROLES are admins;
        everything else is treated as a standard (low-privilege) user."""
        self.replay = replay
        self.identities = identities

    def _standard_users(self) -> List[str]:
        return [i for i, r in self.identities.items() if (r or "").lower() not in ADMIN_ROLES]

    def _admins(self) -> List[str]:
        return [i for i, r in self.identities.items() if (r or "").lower() in ADMIN_ROLES]

    def _safe_replay(self, request: Dict[str, Any], identity_id: Optional[str]) -> ReplayResponse:
        try:
            return self.replay(request, identity_id)
        except Exception as e:
            logger.warning("role_escalation: replay failed (%s)", e)
            return ReplayResponse(status=0)

    def analyze_resource(self, resource: ResourceCrud,
                         owner_id: Optional[str] = None) -> List[EscalationFinding]:
        """create as owner → cross-access as every peer and unauthenticated."""
        findings: List[EscalationFinding] = []
        standard = self._standard_users()
        owner = owner_id or (standard[0] if standard else None)
        if owner is None:
            return findings

        if resource.create:
            self._safe_replay(resource.create, owner)  # establish ownership

        cross_ops = [("read", resource.read), ("update", resource.update),
                     ("delete", resource.delete)]

        # Horizontal: each peer standard user accessing the owner's resource.
        for peer in [u for u in standard if u != owner]:
            for op_name, op_req in cross_ops:
                if not op_req:
                    continue
                resp = self._safe_replay(op_req, peer)
                if resp.status in SUCCESS_STATUSES:
                    findings.append(EscalationFinding(
                        test="bola",
                        scenario=f"{op_name} owner {owner}'s {resource.name} as peer {peer}",
                        resource=resource.name, operation=op_name, actor=peer,
                        victim=owner, status=resp.status,
                        severity="critical" if op_name in ("update", "delete") else "high"))

        # Unauthenticated access to the owner's resource.
        for op_name, op_req in cross_ops:
            if not op_req:
                continue
            resp = self._safe_replay(op_req, None)
            if resp.status in SUCCESS_STATUSES:
                findings.append(EscalationFinding(
                    test="auth_bypass",
                    scenario=f"{op_name} {resource.name} unauthenticated",
                    resource=resource.name, operation=op_name, actor=None,
                    victim=owner, status=resp.status, severity="critical"))
        return findings

    def test_vertical(self, admin_requests: List[Dict[str, Any]]) -> List[EscalationFinding]:
        """Low-privilege identities hitting admin-only endpoints."""
        findings: List[EscalationFinding] = []
        for low in self._standard_users():
            for req in admin_requests:
                resp = self._safe_replay(req, low)
                if resp.status in SUCCESS_STATUSES:
                    findings.append(EscalationFinding(
                        test="vertical_escalation",
                        scenario=f"standard user {low} accessed admin {req.get('url','')}",
                        resource=req.get("url", ""), operation=req.get("method", "GET"),
                        actor=low, victim="admin", status=resp.status, severity="critical"))
        return findings


_ADMIN_URL_HINTS = ("/admin", "/administrator", "/manage", "/internal", "/staff",
                    "/superuser", "/root", "/console", "/dashboard/admin")


def looks_like_admin_endpoint(url: str) -> bool:
    return any(h in url.lower() for h in _ADMIN_URL_HINTS)


class RoleEscalationExecutor(GenericHTTPExecutor):

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        base = self._base(experiment)
        if not base:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                   error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()

        # identities: [{id, role, token?, cookie?, headers?}]; unauth = no auth.
        raw_ids = experiment.input_parameters.get("identities") or []
        identities: Dict[str, str] = {}
        id_headers: Dict[str, Dict[str, str]] = {}
        for spec in raw_ids:
            if not isinstance(spec, dict) or not spec.get("id"):
                continue
            iid = spec["id"]
            identities[iid] = spec.get("role", "standard")
            hdrs = dict(spec.get("headers") or {})
            if spec.get("token"):
                hdrs["Authorization"] = f"Bearer {spec['token']}"
            if spec.get("cookie"):
                hdrs["Cookie"] = spec["cookie"]
            id_headers[iid] = hdrs

        def _replay(request: Dict[str, Any], identity_id: Optional[str]) -> ReplayResponse:
            method = (request.get("method") or "GET").upper()
            pd = request.get("post_data") or ""
            data = pd.encode("utf-8") if (pd and method != "GET") else None
            hdrs = {"User-Agent": "AntiGravity-V2/1.0", **(request.get("headers") or {})}
            if identity_id and identity_id in id_headers:
                hdrs.update(id_headers[identity_id])
            status, body, _ = self._probe(request.get("url", ""), method=method,
                                          headers=hdrs, data=data)
            return ReplayResponse(status=status, body=body or "")

        analyzer = RoleEscalationAnalyzer(_replay, identities)
        findings: List[Dict[str, Any]] = []

        # CRUD resources supplied explicitly, else synthesize per endpoint.
        for res in self._build_resources(experiment, base):
            for f in analyzer.analyze_resource(res):
                findings.append(f.to_dict())

        # Vertical: probe admin-looking endpoints as low-priv identities.
        admin_reqs = [{"method": "GET", "url": u} for u in self._admin_urls(experiment, base)]
        if admin_reqs:
            for f in analyzer.test_vertical(admin_reqs):
                findings.append(f.to_dict())

        evidence = self.collect_evidence({
            "escalation_findings": findings, "findings_count": len(findings),
            "identities_tested": list(identities.keys()),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)

    def _build_resources(self, experiment: SecurityExperiment, base: str) -> List[ResourceCrud]:
        explicit = experiment.input_parameters.get("crud_resources")
        if isinstance(explicit, list) and explicit:
            out = []
            for r in explicit:
                if isinstance(r, dict) and r.get("name"):
                    out.append(ResourceCrud(
                        name=r["name"], create=r.get("create"), read=r.get("read"),
                        update=r.get("update"), delete=r.get("delete")))
            if out:
                return out
        # Synthesize a RUD resource per discovered endpoint carrying an id.
        resources: List[ResourceCrud] = []
        for path in self._all_endpoints_as_paths(experiment)[:15]:
            url = f"{base}{path}"
            resources.append(ResourceCrud(
                name=path,
                read={"method": "GET", "url": url},
                update={"method": "PUT", "url": url, "post_data": json.dumps({"x": 1})},
                delete={"method": "DELETE", "url": url}))
        return resources

    def _admin_urls(self, experiment: SecurityExperiment, base: str) -> List[str]:
        out = []
        for path in self._all_endpoints_as_paths(experiment):
            url = f"{base}{path}"
            if looks_like_admin_endpoint(url):
                out.append(url)
        return out[:10]
