"""Shared glue between the benchmark suites and the scan pipeline.

``findings_to_challenge_ids`` (pure, testable) maps a scan's findings to the
benchmark challenges they solve. ``scan_and_collect_findings`` runs a real scan
and is only used in CI against a live target.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


def _finding_vuln_class(f: Dict[str, Any]) -> str:
    return str(f.get("vuln_class") or f.get("type") or f.get("test") or "").lower()


def findings_to_challenge_ids(findings: List[Dict[str, Any]], catalog: List[Any]) -> Set[str]:
    """A challenge is solved when the scan produced a finding of its vuln_class."""
    found_classes = {_finding_vuln_class(f) for f in findings}
    return {ch.id for ch in catalog if ch.vuln_class.lower() in found_classes}


def scan_and_collect_findings(target: str) -> List[Dict[str, Any]]:  # pragma: no cover
    """Run a POC scan against `target` and return its findings. Requires the
    full pipeline + a reachable target (CI only)."""
    try:
        from core.orchestration.central_brain import CentralBrain
        import asyncio
        brain = CentralBrain(target=target, scope={"domains": [target]})
        asyncio.run(brain.run(phases=["RECON", "ACTIVE_SCANNING"]))
        return list(getattr(brain.ctx, "vulnerabilities", []) or [])
    except Exception as e:
        logger.warning("scan_adapter: live scan failed (%s)", e)
        return []
