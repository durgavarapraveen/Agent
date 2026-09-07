"""
P1-4: replace the generic objective with a target-specific plan.

Given a normalized target summary (asset class, tech stack, endpoints,
params, auth state), emit a prioritized list of vulnerability classes
worth investigating. The planner uses this instead of a static
"try every tool" checklist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


PRIORITY_ORDER = ("P1", "P2", "P3", "P4")


@dataclass
class TargetSummary:
    target: str
    asset_class: str = "UNKNOWN"
    technologies: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    auth_state: str = "unknown"   # anonymous | partial | authenticated
    exposed_files: List[str] = field(default_factory=list)
    api_bases: List[str] = field(default_factory=list)


@dataclass
class PlanItem:
    priority: str
    vuln_class: str
    rationale: str
    targets: List[str] = field(default_factory=list)


def build_plan(summary: TargetSummary) -> List[PlanItem]:
    items: List[PlanItem] = []

    def add(pri: str, cls: str, why: str, targets: List[str] = None):
        items.append(PlanItem(priority=pri, vuln_class=cls, rationale=why,
                              targets=targets or []))

    ac = (summary.asset_class or "").upper()
    tech = [t.lower() for t in summary.technologies]

    # ---- P1: highest signal-to-noise attack surface ----
    if summary.exposed_files:
        add("P1", "FILE_EXPOSURE",
            "exposed paths were observed",
            summary.exposed_files)

    id_params = [p for p in summary.parameters
                 if any(k in p.lower() for k in ("id", "uid", "user", "order", "acc"))]
    if id_params:
        add("P1", "IDOR",
            "ID-shaped parameters detected — object isolation must be tested",
            id_params)

    search_params = [p for p in summary.parameters
                     if any(k in p.lower() for k in ("q", "search", "query", "filter"))]
    if search_params:
        add("P1", "SQLI",
            "search-like parameters — try error/boolean/time-based injection",
            search_params)

    if summary.api_bases and summary.auth_state != "authenticated":
        add("P1", "BROKEN_ACCESS_CONTROL",
            "API surface reachable without authentication",
            summary.api_bases)

    # ---- P2: injection + auth once P1 is exercised ----
    if ac in ("LIVE_APP", "API"):
        add("P2", "AUTHENTICATION",
            "live app requires credential / session hardening review")
        add("P2", "AUTHORIZATION",
            "test horizontal/vertical privilege escalation on discovered endpoints")

    if any(t in tech for t in ("php", "wordpress", "laravel", "django", "flask", "express")):
        add("P2", "INJECTION",
            f"framework in use ({tech}) has historically vulnerable sinks")

    # ---- P3: XSS / CORS / headers ----
    if ac in ("LIVE_APP", "STATIC_SITE"):
        add("P3", "XSS", "reflected/stored/DOM-based XSS on rendered pages")
        add("P3", "CORS", "audit Access-Control-Allow-* headers on API endpoints")
        add("P3", "MISSING_SECURITY_HEADERS", "HSTS / CSP / XFO / referrer-policy")

    # ---- P4: generic brute force only when nothing else lands ----
    add("P4", "DIRECTORY_BRUTEFORCE",
        "fallback content discovery — deprioritize when endpoints already known",
        summary.endpoints)
    add("P4", "TLS_ANALYSIS", "cipher/protocol hygiene")

    # Keep the order stable P1 -> P4
    items.sort(key=lambda it: PRIORITY_ORDER.index(it.priority))
    return items


def render_plan(plan: List[PlanItem]) -> str:
    """Compact human-readable form for LLM context injection."""
    lines: List[str] = []
    cur_pri = None
    for item in plan:
        if item.priority != cur_pri:
            lines.append(f"{item.priority}:")
            cur_pri = item.priority
        line = f"  - {item.vuln_class}: {item.rationale}"
        if item.targets:
            line += f" (targets: {', '.join(item.targets[:5])}{'...' if len(item.targets) > 5 else ''})"
        lines.append(line)
    return "\n".join(lines)
