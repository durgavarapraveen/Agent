"""Phase 5.1 — Hardened browser worker.

Sandbox-enabled, isolated profiles, ephemeral storage, restricted downloads,
request interception, navigation limits, and browser-version pinning.

Phase 5.2 — Browser traffic and DOM observability.

Captures navigation, requests, responses, redirects, DOM snapshots, console events,
storage mutations, service worker activity, and frames. Normalizes into evidence model.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class BrowserSecurityPolicy:
    sandbox_enabled: bool = True
    isolated_profile: bool = True
    ephemeral_storage: bool = True
    allow_downloads: bool = False
    allowed_schemes: frozenset = frozenset({"http", "https"})
    max_navigation_depth: int = 10
    max_requests_per_page: int = 500
    request_timeout_ms: int = 30_000
    blocked_resource_types: frozenset = frozenset({"media", "font"})
    pinned_browser_version: str = ""


@dataclass
class BrowserObservation:
    observation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    observation_type: str = ""
    url: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    is_untrusted: bool = True


class BrowserWorker:
    """Hardened browser worker with full observability."""

    def __init__(self, policy: BrowserSecurityPolicy = None,
                 egress_checker: Callable[[str], bool] = None):
        self.policy = policy or BrowserSecurityPolicy()
        self._egress_checker = egress_checker
        self._lock = threading.RLock()
        self._observations: List[BrowserObservation] = []
        self._navigation_depth = 0
        self._request_count = 0
        self._session_id = uuid.uuid4().hex
        self._active = False
        self._interceptors: List[Callable] = []

    def start_session(self) -> str:
        with self._lock:
            self._observations.clear()
            self._navigation_depth = 0
            self._request_count = 0
            self._session_id = uuid.uuid4().hex
            self._active = True
        logger.info(f"[BrowserWorker] Session {self._session_id} started "
                     f"(sandbox={self.policy.sandbox_enabled})")
        return self._session_id

    def end_session(self) -> List[BrowserObservation]:
        with self._lock:
            self._active = False
            obs = list(self._observations)
            self._observations.clear()
        logger.info(f"[BrowserWorker] Session {self._session_id} ended, "
                     f"{len(obs)} observations collected")
        return obs

    def authorize_navigation(self, url: str) -> bool:
        scheme = url.split("://")[0].lower() if "://" in url else ""
        if scheme and scheme not in self.policy.allowed_schemes:
            self._record("navigation_blocked", url, {"reason": f"scheme {scheme} not allowed"})
            return False
        if self._navigation_depth >= self.policy.max_navigation_depth:
            self._record("navigation_blocked", url, {"reason": "max depth exceeded"})
            return False
        if self._egress_checker and not self._egress_checker(url):
            self._record("navigation_blocked", url, {"reason": "egress policy denied"})
            return False
        return True

    def authorize_request(self, url: str, resource_type: str = "") -> bool:
        if self._request_count >= self.policy.max_requests_per_page:
            return False
        if resource_type in self.policy.blocked_resource_types:
            return False
        if not self.policy.allow_downloads and resource_type == "download":
            return False
        if self._egress_checker and not self._egress_checker(url):
            self._record("request_blocked", url, {"reason": "egress policy denied"})
            return False
        self._request_count += 1
        return True

    def record_navigation(self, url: str, status_code: int = 200) -> None:
        self._navigation_depth += 1
        self._record("navigation", url, {"status_code": status_code, "depth": self._navigation_depth})

    def record_request(self, url: str, method: str, headers: dict = None,
                       body: str = "") -> str:
        obs = self._record("request", url, {
            "method": method,
            "headers": headers or {},
            "body_length": len(body),
        })
        return obs.observation_id

    def record_response(self, url: str, status_code: int, headers: dict = None,
                        body_length: int = 0, request_id: str = "") -> str:
        obs = self._record("response", url, {
            "status_code": status_code,
            "headers": headers or {},
            "body_length": body_length,
            "request_id": request_id,
        })
        return obs.observation_id

    def record_redirect(self, from_url: str, to_url: str, status_code: int) -> None:
        self._record("redirect", from_url, {"to_url": to_url, "status_code": status_code})

    def record_dom_snapshot(self, url: str, html_hash: str, element_count: int) -> None:
        self._record("dom_snapshot", url, {"html_hash": html_hash, "element_count": element_count})

    def record_console_event(self, level: str, message: str, url: str = "") -> None:
        self._record("console", url, {"level": level, "message": message[:2000]})

    def record_storage_mutation(self, storage_type: str, key: str, url: str = "") -> None:
        self._record("storage_mutation", url, {"storage_type": storage_type, "key": key})

    def record_service_worker(self, event_type: str, scope: str, url: str = "") -> None:
        self._record("service_worker", url, {"event_type": event_type, "scope": scope})

    def record_frame(self, frame_url: str, parent_url: str, is_cross_origin: bool) -> None:
        self._record("frame", frame_url, {"parent_url": parent_url, "cross_origin": is_cross_origin})

    def record_websocket(self, url: str, direction: str, data_length: int) -> None:
        self._record("websocket", url, {"direction": direction, "data_length": data_length})

    def get_observations(self, obs_type: str = "", limit: int = 500) -> List[BrowserObservation]:
        with self._lock:
            if obs_type:
                filtered = [o for o in self._observations if o.observation_type == obs_type]
            else:
                filtered = list(self._observations)
        return filtered[-limit:]

    def export_evidence(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "observation_id": o.observation_id,
                    "timestamp": o.timestamp,
                    "type": o.observation_type,
                    "url": o.url,
                    "data": o.data,
                    "is_untrusted": o.is_untrusted,
                    "session_id": self._session_id,
                }
                for o in self._observations
            ]

    def _record(self, obs_type: str, url: str, data: dict) -> BrowserObservation:
        obs = BrowserObservation(
            observation_type=obs_type,
            url=url,
            data=data,
        )
        with self._lock:
            self._observations.append(obs)
        return obs
