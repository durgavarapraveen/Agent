"""Tech-research front-end (Tester.txt Phase 1 "known issues").

When the agent fingerprints a technology it researches *known* vulnerabilities
for it — CVEs via the existing NVD feed client — and surfaces them so hypothesis
generation is grounded in real, tech-specific issues rather than only generic
patterns. Bounded + process-cached; reuses `vuln_intel.feeds.FeedClient`.

Reusable: `research_technologies(...)` (structured, for threat model/report) and
`known_issues_text(...)` (prompt injection for the hypothesis engine).
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

_CACHE: Dict[str, List[Dict[str, Any]]] = {}
_MAX_TECHS = 8
_MAX_CVES = 3

_VER_RE = re.compile(r"([a-zA-Z0-9_.\- ]+?)[/ ]?v?(\d+(?:\.\d+){0,2})?$")


def _norm_tech(t: Any) -> Tuple[str, str]:
    if isinstance(t, dict):
        name = str(t.get("name", "") or t.get("technology", ""))
        ver = str(t.get("version", "") or "")
        return name.strip(), ver.strip()
    s = str(t or "").strip()
    m = _VER_RE.match(s)
    if m:
        return (m.group(1) or s).strip(), (m.group(2) or "").strip()
    return s, ""


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def research_technologies(technologies: List[Any]) -> List[Dict[str, Any]]:
    """Return known-issue records for the detected stack:
    [{tech, version, cve_id, cvss, severity, description}]. Bounded + cached."""
    if not technologies:
        return []
    try:
        from core.intelligence.vuln_intel.feeds import FeedClient
    except Exception as e:  # feeds unavailable → no-op
        logger.debug("[TechResearch] feeds unavailable: %s", e)
        return []

    api_key = os.getenv("NVD_API_KEY", "").strip() or None
    client = FeedClient(timeout=5, api_key=api_key, offline_mode=False)

    out: List[Dict[str, Any]] = []
    seen_tech: set = set()
    for t in technologies:
        if len(seen_tech) >= _MAX_TECHS:
            break
        name, ver = _norm_tech(t)
        if not name or name.lower() in seen_tech:
            continue
        seen_tech.add(name.lower())
        key = f"{name.lower()}:{ver.lower()}"
        cves = _CACHE.get(key)
        if cves is None:
            try:
                cves = client.search_cve_for_software(name, ver)[:_MAX_CVES]
            except Exception as e:
                logger.debug("[TechResearch] CVE lookup failed for %s: %s", name, e)
                cves = []
            _CACHE[key] = cves
        for c in cves:
            score = float(c.get("cvss_score", 0.0) or 0.0)
            out.append({
                "tech": name, "version": ver,
                "cve_id": c.get("cve_id", ""),
                "cvss": score, "severity": _severity_from_cvss(score),
                "description": (c.get("description", "") or "")[:400],
            })
    if out:
        logger.info("[TechResearch] %d known issue(s) across %d tech(s)",
                    len(out), len(seen_tech))
    return out


def known_issues_text(technologies: List[Any], max_items: int = 12) -> str:
    """Formatted known-issue block for hypothesis-prompt injection."""
    issues = research_technologies(technologies)
    if not issues:
        return ""
    lines = ["Known issues for detected technologies (research these):"]
    for it in issues[:max_items]:
        lines.append(f"- {it['tech']} {it['version']}: {it['cve_id']} "
                     f"({it['severity']}) {it['description'][:160]}")
    return "\n".join(lines)
