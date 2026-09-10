from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class NormalizedState:
    target: str
    assets: List[str] = field(default_factory=list)
    live_apps: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    auth: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    open_hypotheses: List[str] = field(default_factory=list)
    rejected_hypotheses: List[str] = field(default_factory=list)
    waf_state: str = "NORMAL"
    tools_executed: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)


def build_state(ctx, waf_mode: str = "NORMAL",
                observations: List[str] = None,
                hypotheses: Dict[str, List[str]] = None,
                tools_executed: List[str] = None,
                missing_evidence: List[str] = None) -> NormalizedState:
    hypotheses = hypotheses or {}
    return NormalizedState(
        target=getattr(ctx, "target", ""),
        assets=list(getattr(ctx, "subdomains", []) or [])[:100],
        live_apps=[e for e in (getattr(ctx, "endpoints", []) or [])
                   if isinstance(e, str) and e.startswith("http")][:50],
        technologies=list(getattr(ctx, "technologies", []) or [])[:30],
        endpoints=list(getattr(ctx, "endpoints", []) or [])[:80],
        parameters=list(getattr(ctx, "parameters", []) or [])[:50],
        auth=(getattr(ctx, "auth", None) or {}) if isinstance(getattr(ctx, "auth", None), dict) else {},
        observations=list(observations or [])[:40],
        open_hypotheses=list(hypotheses.get("open", []) or [])[:20],
        rejected_hypotheses=list(hypotheses.get("rejected", []) or [])[:20],
        waf_state=waf_mode,
        tools_executed=list(tools_executed or [])[:50],
        missing_evidence=list(missing_evidence or [])[:20],
    )


def render(state: NormalizedState) -> str:
    def lst(name: str, items: List[str], cap: int = 20) -> str:
        if not items:
            return f"{name}: (none)"
        head = items[:cap]
        more = "" if len(items) <= cap else f" ... (+{len(items)-cap} more)"
        return f"{name}: " + ", ".join(str(i) for i in head) + more

    lines = [
        f"Target: {state.target}",
        lst("Assets", state.assets),
        lst("Live applications", state.live_apps, cap=10),
        lst("Technologies", state.technologies, cap=15),
        lst("Endpoints", state.endpoints, cap=25),
        lst("Parameters", state.parameters, cap=20),
        f"Authentication: {state.auth or 'none observed'}",
        lst("Known observations", state.observations, cap=15),
        lst("Open hypotheses", state.open_hypotheses),
        lst("Rejected hypotheses", state.rejected_hypotheses),
        f"WAF state: {state.waf_state}",
        lst("Tools already executed", state.tools_executed, cap=25),
        lst("Missing evidence", state.missing_evidence),
    ]
    return "\n".join(lines)
