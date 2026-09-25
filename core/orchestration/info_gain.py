"""Information-gain action selection (spec Phase 10/12).

The agentic executor selects actions by LLM function-calling. Left alone it
optimizes for "make a tool call", which is why the logs show many calls and few
distinct, high-value actions. This module adds a deterministic planner that,
from the current structured state, generates candidate next actions and ranks
them by EXPECTED INFORMATION GAIN — novelty (not already tried, via the
ActionLedger), whether the (parameter, payload-class) pair is still untested,
and the value potential of the target — so the executor prefers the action that
reduces uncertainty or unlocks an attack path over redundant probing.

Factors are transparent and stored on each candidate (spec Phase 32). No LLM
computes the ranking; the LLM still executes, but it is steered toward the
high-value frontier rather than re-deriving it from scratch each prompt.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.orchestration.action_ledger import action_fingerprint, get_ledger

# Payload classes worth trying per parameter context, and their base value.
_CLASS_VALUE = {"sqli": 0.9, "idor": 0.9, "authz": 0.9, "ssrf": 0.8,
                "xss": 0.6, "traversal": 0.7, "generic": 0.3}

# Which classes are relevant for a parameter given light context signals.
def _relevant_classes(param: Dict[str, Any]) -> List[str]:
    name = str(param.get("name", "")).lower()
    classes: List[str] = []
    if any(k in name for k in ("id", "uid", "user", "account", "order", "doc", "file")):
        classes += ["idor", "sqli"]
    if any(k in name for k in ("q", "search", "query", "name", "comment", "message")):
        classes += ["xss", "sqli"]
    if any(k in name for k in ("url", "uri", "redirect", "callback", "next", "dest")):
        classes += ["ssrf"]
    if any(k in name for k in ("path", "file", "dir", "template", "page")):
        classes += ["traversal"]
    if not classes:
        classes = ["sqli", "xss"]
    # de-dupe, preserve order
    seen, out = set(), []
    for c in classes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


@dataclass
class ActionCandidate:
    tool: str
    operation: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    payload_class: str = "generic"
    rationale: str = ""
    factors: Dict[str, float] = field(default_factory=dict)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool, "operation": self.operation, "target": self.target,
            "params": self.params, "payload_class": self.payload_class,
            "rationale": self.rationale, "factors": self.factors,
            "score": round(self.score, 4),
        }


def _param_value(param: Dict[str, Any]) -> float:
    """Target value potential from light context: auth boundary / data / reflection."""
    v = 0.4
    if param.get("auth_context") and param.get("auth_context") != "anon":
        v += 0.3  # behind auth = higher value (authz/IDOR reachable)
    if param.get("reflects") or param.get("reflection"):
        v += 0.2
    if param.get("returns_data") or param.get("sink"):
        v += 0.2
    return min(v, 1.0)


def generate_candidates(state: Dict[str, Any]) -> List[ActionCandidate]:
    """Derive candidate probe actions from untested (parameter, class) pairs."""
    out: List[ActionCandidate] = []
    for param in state.get("parameters", []) or []:
        if not isinstance(param, dict) or not param.get("name"):
            continue
        endpoint = param.get("endpoint") or param.get("location") or ""
        tested = {str(c).lower() for c in (param.get("tested_classes") or [])}
        for cls in _relevant_classes(param):
            if cls in tested:
                continue
            out.append(ActionCandidate(
                tool=_tool_for(cls), operation=cls, target=endpoint,
                params={"parameter": param["name"], "method": param.get("method", "GET"),
                        "_payload_class": cls,
                        "identity": param.get("auth_context", "")},
                payload_class=cls,
                rationale=f"untested {cls} on parameter '{param['name']}'"))
    return out


_TOOL_FOR = {"sqli": "sqlmap", "xss": "dalfox", "idor": "http",
             "authz": "http", "ssrf": "http", "traversal": "ffuf"}


def _tool_for(cls: str) -> str:
    return _TOOL_FOR.get(cls, "http")


def expected_info_gain(candidate: ActionCandidate, state: Dict[str, Any],
                       session_id: str = "") -> ActionCandidate:
    """Score a candidate by transparent factors; stores them on the candidate."""
    ledger = get_ledger(session_id)
    fp = action_fingerprint(candidate.tool, candidate.operation, candidate.target,
                            candidate.params)
    novelty = 0.0 if ledger.seen(fp) else 1.0

    # Untested (param, class): find the owning param in state.
    pname = str(candidate.params.get("parameter", "")).lower()
    untested = 1.0
    pvalue = 0.4
    for p in state.get("parameters", []) or []:
        if str(p.get("name", "")).lower() == pname and \
                (p.get("endpoint") or p.get("location")) == candidate.target:
            tested = {str(c).lower() for c in (p.get("tested_classes") or [])}
            untested = 0.0 if candidate.payload_class in tested else 1.0
            pvalue = _param_value(p)
            break

    class_value = _CLASS_VALUE.get(candidate.payload_class, 0.3)
    cost = 1.0  # single probe
    factors = {
        "novelty": round(novelty, 3),
        "untested_class": round(untested, 3),
        "class_value": round(class_value, 3),
        "target_value": round(pvalue, 3),
        "cost_efficiency": round(cost, 3),
    }
    weights = {"novelty": 0.35, "untested_class": 0.25, "class_value": 0.20,
               "target_value": 0.15, "cost_efficiency": 0.05}
    candidate.factors = factors
    candidate.score = round(sum(factors[k] * w for k, w in weights.items()), 4)
    return candidate


def rank_candidates(state: Dict[str, Any], session_id: str = "",
                    limit: int = 10) -> List[ActionCandidate]:
    scored = [expected_info_gain(c, state, session_id)
              for c in generate_candidates(state)]
    # The ActionLedger is authoritative for "already tried": a candidate it has
    # seen (novelty 0) has no information gain and is dropped, regardless of the
    # parameter's own tested-class history.
    scored = [c for c in scored if c.score > 0.0 and c.factors["novelty"] > 0.0]
    scored.sort(key=lambda c: c.score, reverse=True)
    return scored[:limit]


def select_next(state: Dict[str, Any], session_id: str = "") -> Optional[ActionCandidate]:
    ranked = rank_candidates(state, session_id, limit=1)
    return ranked[0] if ranked else None


# ── ctx bridge (best-effort state extraction) ──────────────────────────
def build_state_from_ctx(ctx: Any) -> Dict[str, Any]:
    """Extract the light state the planner needs from a scan context.

    Reads parameters (with any tested-class history), endpoints and findings.
    Tolerant of missing attributes — returns empty lists rather than raising.
    """
    def _g(name, default=None):
        try:
            return getattr(ctx, name, default) if not hasattr(ctx, "get") \
                else (ctx.get(name, default) if callable(getattr(ctx, "get")) else getattr(ctx, name, default))
        except Exception:
            return default

    params: List[Dict[str, Any]] = []
    raw = _g("parameters", []) or _g("parameter_inventory", []) or []
    if isinstance(raw, dict):
        raw = list(raw.values())
    for p in raw or []:
        if isinstance(p, dict):
            params.append(p)
        else:
            params.append({"name": getattr(p, "name", str(p)),
                           "endpoint": getattr(p, "endpoint", ""),
                           "tested_classes": getattr(p, "tested_classes", [])})

    endpoints = _g("endpoints", {}) or {}
    endpoints = list(endpoints.keys()) if isinstance(endpoints, dict) else list(endpoints or [])
    return {
        "parameters": params,
        "endpoints": [str(e) for e in endpoints],
        "findings": list(_g("vulnerabilities", []) or []),
    }


def priority_actions_hint(ctx: Any, session_id: str = "", top: int = 5) -> str:
    """Compact text block of the highest-info-gain next actions, to steer the
    executor. Empty string when there is nothing high-value to suggest."""
    state = build_state_from_ctx(ctx)
    ranked = rank_candidates(state, session_id, limit=top)
    if not ranked:
        return ""
    lines = ["HIGH-VALUE NEXT ACTIONS (by expected information gain):"]
    for i, c in enumerate(ranked, 1):
        lines.append(f"  {i}. {c.operation} on {c.target} "
                     f"[param={c.params.get('parameter')}] "
                     f"— {c.rationale} (score={c.score})")
    return "\n".join(lines)
