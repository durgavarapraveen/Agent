"""Phase 6.3 — parallel domain-specialist swarm.

Runs domain specialists concurrently, each owning a family of executors:

  * auth        — authentication / authorization / role-escalation;
  * injection   — SQLi / XSS / command / path traversal;
  * business_logic — workflow crawler + mutation engine + ecommerce;
  * api         — mass assignment / BOLA / excessive data exposure.

A coordinator assigns each endpoint to the specialists that apply (deduping so a
specialist never tests the same endpoint twice), runs them in parallel via the
existing ``ParallelExecutor``, and merges every specialist's findings into one
shared, deduplicated feed (mirroring a single ``FindingStoreV2`` with dedup).

The routing and dedup are pure; execution uses an injectable async ``runner``,
so the swarm is unit-testable with no real executors or network.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from core.discovery.workflow_crawler import normalize_path

logger = logging.getLogger(__name__)

# specialist → substrings that route an endpoint to it.
_SPECIALIST_HINTS = {
    "auth": ("login", "logout", "auth", "oauth", "token", "session", "sso",
             "password", "signin", "signup", "register", "admin", "account"),
    "business_logic": ("cart", "basket", "checkout", "order", "payment", "pay",
                       "coupon", "discount", "invoice", "workflow", "transfer"),
    "api": ("/api", "graphql", "/v1", "/v2", "/rest", ".json"),
}
# injection applies to anything that takes input (params or a body method).
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SPECIALIST_CAPABILITIES = {
    "auth": ["authentication", "authorization", "role_escalation"],
    "injection": ["sql_injection", "xss", "command_injection", "path_traversal"],
    "business_logic": ["business_logic", "ecommerce", "workflow"],
    "api": ["api_mass_assignment", "bola", "excessive_data_exposure"],
}

# runner(specialist_name, endpoints) -> list of finding dicts
Runner = Callable[[str, List[Dict[str, Any]]], Awaitable[List[Dict[str, Any]]]]


def _ep_url(ep: Any) -> str:
    return ep.get("url", "") if isinstance(ep, dict) else getattr(ep, "url", str(ep))


def _ep_method(ep: Any) -> str:
    m = ep.get("method", "GET") if isinstance(ep, dict) else getattr(ep, "method", "GET")
    return (m or "GET").upper()


def _ep_has_params(ep: Any) -> bool:
    if isinstance(ep, dict):
        return bool(ep.get("params")) or "?" in _ep_url(ep) or _ep_method(ep) in _STATE_METHODS
    return _ep_method(ep) in _STATE_METHODS or "?" in _ep_url(ep)


def _ep_key(ep: Any) -> str:
    return f"{_ep_method(ep)} {normalize_path(_ep_url(ep))}"


def assign_endpoints(endpoints: List[Any]) -> Dict[str, List[Any]]:
    """Route each endpoint to the specialists that apply, deduped per specialist."""
    assignments: Dict[str, List[Any]] = {s: [] for s in SPECIALIST_CAPABILITIES}
    seen: Dict[str, set] = {s: set() for s in SPECIALIST_CAPABILITIES}

    def _add(specialist: str, ep: Any):
        key = _ep_key(ep)
        if key not in seen[specialist]:
            seen[specialist].add(key)
            assignments[specialist].append(ep)

    for ep in endpoints:
        url = _ep_url(ep).lower()
        for specialist, hints in _SPECIALIST_HINTS.items():
            if any(h in url for h in hints):
                _add(specialist, ep)
        if _ep_has_params(ep):
            _add("injection", ep)
    return {s: eps for s, eps in assignments.items() if eps}


@dataclass
class SwarmResult:
    assignments: Dict[str, int]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    duplicates_dropped: int = 0
    specialists_run: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"assignments": self.assignments, "findings": self.findings,
                "finding_count": len(self.findings),
                "duplicates_dropped": self.duplicates_dropped,
                "specialists_run": self.specialists_run}


class SpecialistCoordinator:

    def __init__(self, runner: Runner, executor: Any = None,
                 dedup_key: Optional[Callable[[Dict[str, Any]], Any]] = None,
                 max_concurrency: int = 4):
        self.runner = runner
        self._dedup_key = dedup_key or (lambda f: (f.get("type") or f.get("test"),
                                                   f.get("url") or f.get("path")))
        if executor is None:
            from core.orchestration.parallel_executor import ParallelExecutor
            executor = ParallelExecutor(max_concurrency=max_concurrency)
        self._executor = executor

    async def run(self, endpoints: List[Any]) -> SwarmResult:
        assignments = assign_endpoints(endpoints)
        if not assignments:
            return SwarmResult(assignments={})

        tasks = [{"task_id": s, "specialist": s, "endpoints": eps}
                 for s, eps in assignments.items()]

        async def _exec(task: Dict[str, Any]):
            return await self.runner(task["specialist"], task["endpoints"])

        results = await self._executor.execute_group(tasks, _exec)

        # Merge into one shared, deduplicated feed.
        feed: List[Dict[str, Any]] = []
        seen = set()
        dups = 0
        specialists_run = []
        for r in results:
            if not getattr(r, "success", False):
                continue
            specialists_run.append(getattr(r, "task_id", "?"))
            for f in (r.result or []):
                key = self._dedup_key(f)
                if key in seen:
                    dups += 1
                    continue
                seen.add(key)
                feed.append(f)

        return SwarmResult(
            assignments={s: len(eps) for s, eps in assignments.items()},
            findings=feed, duplicates_dropped=dups,
            specialists_run=sorted(specialists_run))
