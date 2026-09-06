"""
Canonical AttackSurfaceState — single authoritative representation
of everything discovered about the target.

Every discovery preserves: id, source, evidence, confidence, first_seen, last_seen.
States: DISCOVERED, INFERRED, HYPOTHESIS, CONFIRMED.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.domain.asset import Application, Host, Technology, Workflow
from core.domain.endpoint import DiscoveryState, Endpoint
from core.domain.identity import Identity
from core.domain.parameter import Parameter
from core.domain.session import Session

logger = logging.getLogger(__name__)


class AttackSurfaceState:
    """
    One authoritative view of the target's attack surface.

    Structure:
      Target
       ├── Assets (domains, subdomains, IPs, ports, services)
       ├── Applications
       ├── Endpoints (HTTP, REST, GraphQL, WebSocket)
       ├── Parameters
       ├── Technologies
       ├── Authentication
       ├── Identities
       ├── Sessions
       ├── Files
       └── Workflows
    """

    def __init__(self, target: str):
        self.target = target
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.applications: Dict[str, Application] = {}
        self.endpoints: Dict[str, Endpoint] = {}
        # Secondary index for O(1) endpoint dedupe by normalized key.
        # Prior implementation scanned `endpoints.values()` on every add,
        # giving O(n²) growth on large scans.
        self._endpoint_key_index: Dict[str, str] = {}  # norm_key -> endpoint_id
        self.parameters: Dict[str, List[Parameter]] = {}
        self.technologies: Dict[str, List[Technology]] = {}
        self.identities: Dict[str, Identity] = {}
        self.sessions: Dict[str, Session] = {}
        self.files: Dict[str, Dict[str, Any]] = {}
        self.workflows: Dict[str, Workflow] = {}

        # Relationship tracking
        self.redirects: Dict[str, str] = {}
        self.related_applications: Dict[str, List[str]] = {}

        # SPA catch-all detection
        self.spa_baselines: Dict[str, Dict[str, Any]] = {}

        # Counters for data flow auditing (Phase 4)
        self._counts = {
            "assets_discovered": 0,
            "applications_discovered": 0,
            "endpoints_discovered": 0,
            "endpoints_normalized": 0,
            "endpoints_deduplicated": 0,
            "endpoints_transferred_to_v2": 0,
            "parameters_discovered": 0,
            "parameters_transferred_to_v2": 0,
        }

    # --- Assets ---

    def add_asset(self, asset_id: str, asset_type: str, data: Dict[str, Any],
                  source: str = "unknown", confidence: float = 1.0,
                  evidence_ids: Optional[List[str]] = None) -> None:
        now = datetime.utcnow().isoformat()
        if asset_id in self.assets:
            self.assets[asset_id]["last_seen"] = now
            if evidence_ids:
                self.assets[asset_id].setdefault("evidence_ids", []).extend(evidence_ids)
            return

        self.assets[asset_id] = {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "source": source,
            "confidence": confidence,
            "evidence_ids": evidence_ids or [],
            "first_seen": now,
            "last_seen": now,
            "discovery_state": DiscoveryState.DISCOVERED.value,
            **data,
        }
        self._counts["assets_discovered"] += 1
        logger.info(f"ASSET_ADDED type={asset_type} id={asset_id} source={source}")

    # --- Applications ---

    def add_application(self, app: Application) -> None:
        if app.id in self.applications:
            self.applications[app.id].updated_at = datetime.utcnow()
            return
        self.applications[app.id] = app
        self._counts["applications_discovered"] += 1
        logger.info(f"APPLICATION_ADDED id={app.id} name={app.name}")

    def add_redirect(self, from_host: str, to_host: str) -> None:
        self.redirects[from_host] = to_host
        logger.info(f"REDIRECT_MAPPED {from_host} -> {to_host}")

    def add_related_application(self, parent_host: str, related_app_id: str) -> None:
        self.related_applications.setdefault(parent_host, [])
        if related_app_id not in self.related_applications[parent_host]:
            self.related_applications[parent_host].append(related_app_id)

    # --- Endpoints ---

    def add_endpoint(self, endpoint: Endpoint,
                     source: str = "unknown") -> bool:
        """Add endpoint with deduplication. Returns True if new.

        O(1) via `_endpoint_key_index` — the previous O(n) linear scan
        compounded to O(n²) over the course of a scan with thousands of
        endpoints.
        """
        norm_key = endpoint.normalized_key()

        existing_id = self._endpoint_key_index.get(norm_key)
        if existing_id is not None:
            existing = self.endpoints.get(existing_id)
            if existing is not None:
                existing.last_seen = datetime.utcnow().isoformat()
                existing.evidence_ids.extend(endpoint.evidence_ids)
                self._counts["endpoints_deduplicated"] += 1
                return False

        endpoint.source = source
        if not endpoint.first_seen:
            endpoint.first_seen = datetime.utcnow().isoformat()
        endpoint.last_seen = endpoint.first_seen
        self.endpoints[endpoint.endpoint_id] = endpoint
        self._endpoint_key_index[norm_key] = endpoint.endpoint_id
        self._counts["endpoints_discovered"] += 1
        self._counts["endpoints_normalized"] += 1
        return True

    # --- Parameters ---

    def add_parameter(self, endpoint_id: str, param: Parameter,
                      source: str = "unknown") -> None:
        self.parameters.setdefault(endpoint_id, [])
        for existing in self.parameters[endpoint_id]:
            if existing.name == param.name and existing.parameter_type == param.parameter_type:
                return
        param.source = source
        self.parameters[endpoint_id].append(param)
        self._counts["parameters_discovered"] += 1

    # --- Technologies ---

    def add_technology(self, host: str, tech: Technology) -> None:
        self.technologies.setdefault(host, [])
        for existing in self.technologies[host]:
            if existing.name == tech.name:
                if tech.version and not existing.version:
                    existing.version = tech.version
                return
        self.technologies[host].append(tech)

    # --- Identities / Sessions ---

    def add_identity(self, identity: Identity) -> None:
        self.identities[identity.identity_id] = identity

    def add_session(self, session: Session) -> None:
        self.sessions[session.session_id] = session

    # --- SPA Detection (Phase 8) ---

    def set_spa_baseline(self, host: str, baseline: Dict[str, Any]) -> None:
        self.spa_baselines[host] = baseline
        logger.info(f"SPA_BASELINE_SET host={host} status={baseline.get('status')} "
                    f"length={baseline.get('content_length')}")

    def is_spa_catch_all(self, host: str, status: int,
                         content_length: int, body_hash: str) -> bool:
        baseline = self.spa_baselines.get(host)
        if not baseline:
            return False
        return (
            baseline.get("status") == status
            and abs(baseline.get("content_length", 0) - content_length) < 50
            and baseline.get("body_hash") == body_hash
        )

    # --- Recon → V2 Transfer Audit (Phase 4) ---

    def log_transfer_counts(self) -> None:
        for key, count in self._counts.items():
            logger.info(f"ATTACK_SURFACE_COUNT {key}={count}")

    def mark_transferred_to_v2(self, endpoints: int, parameters: int) -> None:
        self._counts["endpoints_transferred_to_v2"] = endpoints
        self._counts["parameters_transferred_to_v2"] = parameters
        self.log_transfer_counts()

    # --- Summary ---

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "assets": len(self.assets),
            "applications": len(self.applications),
            "endpoints": len(self.endpoints),
            "parameters": sum(len(v) for v in self.parameters.values()),
            "technologies": sum(len(v) for v in self.technologies.values()),
            "identities": len(self.identities),
            "sessions": len(self.sessions),
            "files": len(self.files),
            "workflows": len(self.workflows),
            "redirects": len(self.redirects),
            "spa_baselines": len(self.spa_baselines),
            "counts": dict(self._counts),
        }
