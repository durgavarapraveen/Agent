"""Phase 8.4 — progressive depth scanning (Tier 0/1/2).

Instead of running all 60+ executors against every endpoint, scan in tiers:

  * Tier 0 — headers & config (no LLM): ALL endpoints. Deterministic only.
  * Tier 1 — common vulns (minimal LLM): endpoints that take input or handle auth.
  * Tier 2 — deep testing (full LLM): endpoints Tier 0/1 flagged, plus inherently
    high-risk endpoints (payment / auth / admin).

Pure partitioning logic — the experiment scheduler consumes the plan in
Tier 0 → 1 → 2 order. Fully testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

TIER0, TIER1, TIER2 = 0, 1, 2

_HIGH_RISK_HINTS = ("payment", "pay", "checkout", "admin", "auth", "login",
                    "token", "billing", "transfer", "password", "oauth")
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_INTERESTING_HINTS = ("login", "auth", "search", "upload", "api", "user", "account")


def _url(ep: Any) -> str:
    return ep.get("url", "") if isinstance(ep, dict) else getattr(ep, "url", str(ep))


def _method(ep: Any) -> str:
    m = ep.get("method", "GET") if isinstance(ep, dict) else getattr(ep, "method", "GET")
    return (m or "GET").upper()


def _has_params(ep: Any) -> bool:
    if isinstance(ep, dict) and ep.get("params"):
        return True
    return "?" in _url(ep) or _method(ep) in _STATE_METHODS


def is_high_risk(ep: Any) -> bool:
    u = _url(ep).lower()
    return any(h in u for h in _HIGH_RISK_HINTS)


def is_interesting(ep: Any) -> bool:
    u = _url(ep).lower()
    return _has_params(ep) or _method(ep) in _STATE_METHODS or any(h in u for h in _INTERESTING_HINTS)


def assign_tier(ep: Any, flagged: bool = False) -> int:
    """Deepest tier an endpoint qualifies for (it still runs the shallower tiers)."""
    if flagged or is_high_risk(ep):
        return TIER2
    if is_interesting(ep):
        return TIER1
    return TIER0


@dataclass
class ProgressiveScanPlan:
    tier0: List[Any] = field(default_factory=list)   # all endpoints
    tier1: List[Any] = field(default_factory=list)
    tier2: List[Any] = field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        return {"tier0": len(self.tier0), "tier1": len(self.tier1), "tier2": len(self.tier2)}

    def ordered(self) -> List[Any]:
        """Endpoints in Tier 0 → 1 → 2 scheduling order (each endpoint once, at
        its deepest tier)."""
        return self.tier0_only() + self.tier1 + self.tier2

    def tier0_only(self) -> List[Any]:
        deeper = {id(e) for e in self.tier1} | {id(e) for e in self.tier2}
        return [e for e in self.tier0 if id(e) not in deeper]


def build_plan(endpoints: List[Any], flagged_urls: Optional[Set[str]] = None) -> ProgressiveScanPlan:
    flagged_urls = flagged_urls or set()
    plan = ProgressiveScanPlan()
    for ep in endpoints:
        plan.tier0.append(ep)  # Tier 0 runs on everything
        tier = assign_tier(ep, flagged=_url(ep) in flagged_urls)
        if tier >= TIER2:
            plan.tier2.append(ep)
        elif tier >= TIER1:
            plan.tier1.append(ep)
    return plan
