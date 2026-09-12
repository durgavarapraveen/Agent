from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict

logger = logging.getLogger(__name__)


class DecisionOwner(str, Enum):
    LLM = "LLM"
    CODE = "CODE"


LLM_DOMAIN = {
    "hypothesis_selection", "evidence_gap_analysis",
    "vuln_class_relevance", "next_investigation", "finding_correlation",
    "hypothesis_prioritization",
}

CODE_DOMAIN = {
    "authorization", "scope_enforcement", "tool_availability",
    "tool_health", "exit_status_interpretation", "rate_limit_state",
    "waf_mode", "timeout_enforcement", "duplicate_suppression",
    "phase_transition_gate", "endpoint_already_tested",
    "policy_restriction",
}


@dataclass
class PolicyVerdict:
    allow: bool
    reason: str = ""
    detail: Dict[str, Any] = None

    @property
    def allowed(self) -> bool:
        """Read-only alias for `allow`. Some callers and verification tooling
        reference `.allowed`; keep both in sync via this property."""
        return self.allow


def who_decides(topic: str) -> DecisionOwner:
    t = (topic or "").lower()
    if t in CODE_DOMAIN:
        return DecisionOwner.CODE
    if t in LLM_DOMAIN:
        return DecisionOwner.LLM
    return DecisionOwner.LLM  # default to reasoning if unknown


def _fail_closed_import(topic: str, module: str, exc: Exception) -> PolicyVerdict:
    logger.warning("[decisions.policy_engine] %s: %s unavailable (%s), failing closed", topic, module, exc)
    return PolicyVerdict(False, f"{module} unavailable (fail-closed per platform contract): {exc}")


_CAPABILITY_TO_WAF = {
    "technology_fingerprinting": "fingerprint",
    "waf_detection": "fingerprint",
    "tls_analysis": "passive",
    "http_analysis": "passive",
    "subdomain_enumeration": "recon",
    "dns_enumeration": "recon",
    "dns_intelligence": "recon",
    "port_scanning": "recon",
    "endpoint_discovery": "crawl",
    "web_crawling": "crawl",
    "javascript_analysis": "crawl",
    "vulnerability_scanning": "active",
    "sql_injection": "active",
    "xss_scanning": "active",
    "authentication_testing": "active",
    "directory_bruteforce": "brute",
    "parameter_discovery": "brute",
    "employee_enumeration": "osint",
    "github_scanning": "osint",
    "threat_intelligence": "osint",
}


def _capability_to_waf_category(raw: str) -> str:
    if raw in _CAPABILITY_TO_WAF:
        return _CAPABILITY_TO_WAF[raw]
    # Unmapped capabilities: allow safely by defaulting to "active" so they
    # run in NORMAL/CAUTIOUS but stop in LOW_RATE/PASSIVE_ONLY.
    return "active" if raw else "passive"


def enforce(topic: str, ctx: Dict[str, Any]) -> PolicyVerdict:
    t = (topic or "").lower()

    if t == "scope_enforcement":
        target = ctx.get("target", "")
        allowed = ctx.get("allowed_targets") or set()
        if allowed and target not in allowed:
            return PolicyVerdict(False, f"target {target} not in allowed scope",
                                 {"target": target})
        return PolicyVerdict(True)

    if t == "waf_mode":
        try:
            from core.adaptation.waf_state import get_waf_state
        except Exception as e:
            return _fail_closed_import(t, "core.adaptation.waf_state", e)
        mode = get_waf_state().mode_for(ctx.get("target", ""))
        raw_category = (ctx.get("tool_category") or "").lower()
        category = _capability_to_waf_category(raw_category)
        if not get_waf_state().is_tool_allowed(ctx.get("target", ""), category):
            return PolicyVerdict(False,
                f"WAF mode {mode.value} forbids category {category!r}",
                {"mode": mode.value, "category": category})
        return PolicyVerdict(True, detail={"mode": mode.value})

    if t == "duplicate_suppression":
        try:
            from core.knowledge.freshness import get_freshness
        except Exception as e:
            return _fail_closed_import(t, "core.knowledge.freshness", e)
        if get_freshness().has_fresh_result(ctx.get("target", ""),
                                            ctx.get("operation", "")):
            return PolicyVerdict(False,
                "fresh result already recorded — skip redundant tool call",
                {"target": ctx.get("target"), "operation": ctx.get("operation")})
        return PolicyVerdict(True)

    if t == "tool_health":
        try:
            from core.tools.tool_health import get_health_manager
        except Exception as e:
            return _fail_closed_import(t, "core.tools.tool_health", e)
        health = get_health_manager().status_of(ctx.get("tool", ""))
        if health and not health.is_available():
            return PolicyVerdict(False,
                f"tool {ctx.get('tool')!r} marked unavailable ({health.last_failure or 'no reason'})",
                {"tool": ctx.get("tool")})
        return PolicyVerdict(True)

    if t == "timeout_enforcement":
        try:
            from core.tools.timeout_classes import budget_for
        except Exception as e:
            return _fail_closed_import(t, "core.tools.timeout_classes", e)
        budget = budget_for(ctx.get("class", "standard"))
        elapsed = float(ctx.get("elapsed_seconds", 0))
        if elapsed >= budget:
            return PolicyVerdict(False,
                f"budget {budget}s exceeded ({elapsed:.1f}s)",
                {"budget_seconds": budget, "elapsed": elapsed})
        return PolicyVerdict(True, detail={"budget_seconds": budget})

    # Unknown topics fail-closed.
    logger.warning("[decisions.policy_engine] unknown topic %r — denied by default", t)
    return PolicyVerdict(False, reason=f"unknown policy topic {t!r} — denied by default")
