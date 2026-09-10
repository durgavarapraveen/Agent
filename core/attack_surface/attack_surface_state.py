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

        # Counters for data flow auditing (Phase 4).
        # P0.1: these are now DERIVED (recomputed from set sizes), never
        # accumulated cumulatively. `endpoints_raw_fed` is the only running
        # tally (every add_endpoint call, new or duplicate); everything else is
        # computed from it and `len(self.endpoints)` so the invariant
        # always holds and "deduplicated" can never exceed the input.
        self._counts = {
            "assets_discovered": 0,
            "applications_discovered": 0,
            "endpoints_raw_fed": 0,        # cumulative add_endpoint calls (new+dup)
            "endpoints_discovered": 0,
            "endpoints_normalized": 0,
            "endpoints_deduplicated": 0,   # duplicates removed = raw_fed - unique (derived)
            "endpoints_unique": 0,
            "endpoints_transferred_to_v2": 0,   # endpoints now present in the V2 surface
            "endpoints_new_last_transfer": 0,   # genuinely-new in the last wire pass
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
        norm_key = endpoint.normalized_key()
        # Every feed attempt counts as raw input (new OR duplicate).
        self._counts["endpoints_raw_fed"] += 1

        existing_id = self._endpoint_key_index.get(norm_key)
        if existing_id is not None:
            existing = self.endpoints.get(existing_id)
            if existing is not None:
                existing.last_seen = datetime.utcnow().isoformat()
                existing.evidence_ids.extend(endpoint.evidence_ids)
                # Do NOT accumulate a "deduplicated" counter here — it is derived
                # from set sizes in `_recompute_counts` (P0.1).
                return False

        # P0.1: give the endpoint its ONE canonical, content-addressed id so the
        # same URL has the same identity in every store. Only override an id that
        # is missing or a random uuid-style id (keep operator/importer-assigned
        # stable ids).
        try:
            eid = endpoint.endpoint_id or ""
            if (not eid) or len(eid) == 36 and eid.count("-") == 4:
                endpoint.endpoint_id = endpoint.canonical_id()
        except Exception:
            if not endpoint.endpoint_id:
                endpoint.endpoint_id = norm_key
        endpoint.source = source
        if not endpoint.first_seen:
            endpoint.first_seen = datetime.utcnow().isoformat()
        endpoint.last_seen = endpoint.first_seen
        self.endpoints[endpoint.endpoint_id] = endpoint
        self._endpoint_key_index[norm_key] = endpoint.endpoint_id
        self._recompute_counts()
        return True

    def _recompute_counts(self) -> None:
        unique = len(self.endpoints)
        raw = self._counts["endpoints_raw_fed"]
        self._counts["endpoints_unique"] = unique
        self._counts["endpoints_discovered"] = unique
        self._counts["endpoints_normalized"] = unique
        self._counts["endpoints_deduplicated"] = max(0, raw - unique)

    def assert_endpoint_invariants(self) -> bool:
        self._recompute_counts()
        raw = self._counts["endpoints_raw_fed"]
        unique = self._counts["endpoints_unique"]
        dedup = self._counts["endpoints_deduplicated"]
        transferred = self._counts["endpoints_transferred_to_v2"]
        ok = (raw >= unique >= 0
              and dedup == raw - unique
              and 0 <= transferred <= unique)
        if not ok:
            logger.error(
                "ENDPOINT_INVARIANT_VIOLATION raw_fed=%s unique=%s deduplicated=%s "
                "transferred_to_v2=%s (require raw>=unique>=0, dedup==raw-unique, "
                "0<=transferred<=unique)", raw, unique, dedup, transferred)
        return ok

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
        self._recompute_counts()
        for key, count in self._counts.items():
            logger.info(f"ATTACK_SURFACE_COUNT {key}={count}")
        self.assert_endpoint_invariants()

    def mark_transferred_to_v2(self, new_endpoints: int, parameters: int) -> None:
        self._recompute_counts()
        self._counts["endpoints_new_last_transfer"] = new_endpoints
        self._counts["endpoints_transferred_to_v2"] = len(self.endpoints)
        self._counts["parameters_transferred_to_v2"] = max(
            self._counts.get("parameters_transferred_to_v2", 0),
            parameters,
        )
        self.log_transfer_counts()

    # --- Summary ---

    def summary(self) -> Dict[str, Any]:
        self._recompute_counts()
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
