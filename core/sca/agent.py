"""Container / dependency SCA agent (spec §5/§20/§21) — static, scope-gated.

Parses dependency manifests + Dockerfiles from a supplied ``{path: content}``
map, matches dependencies against an advisory source, and analyzes Dockerfiles
for container weaknesses. Deterministic, read-only (no code executed), and
Engagement scope-gated on the target asset. Returns structured findings plus
attack paths for the CRITICAL vulnerable dependencies (a reachable component
RCE is an initial-access edge).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from core.sca.advisories import AdvisorySource, StaticAdvisorySource
from core.sca.dockerfile import analyze_dockerfile
from core.sca.matcher import match
from core.sca.parsers import parse_files, parser_for

logger = logging.getLogger(__name__)


def _is_dockerfile(path: str) -> bool:
    base = path.replace("\\", "/").split("/")[-1].lower()
    return base == "dockerfile" or base.startswith("dockerfile.")


class ScaAgent:
    def __init__(self, files: Dict[str, str],
                 advisory_source: Optional[AdvisorySource] = None,
                 target: str = "artifact", engagement: Optional[Any] = None):
        self.files = files or {}
        self.advisory_source = advisory_source or StaticAdvisorySource([])
        self.target = target
        self.engagement = engagement

    @classmethod
    def from_advisories(cls, files: Dict[str, str], advisories: List[Any],
                        target: str = "artifact",
                        engagement: Optional[Any] = None) -> "ScaAgent":
        return cls(files, StaticAdvisorySource(advisories), target, engagement)

    def _authorized(self) -> bool:
        if self.engagement is None:
            return True
        try:
            return bool(self.engagement.is_resource_authorized(self.target))
        except Exception:
            return False  # fail closed

    def run(self) -> Dict[str, Any]:
        if not self._authorized():
            logger.warning("[sca] target %r not authorized by engagement; skipping",
                           self.target)
            return {"target": self.target, "packages": 0,
                    "findings": [], "attack_paths": [],
                    "ecosystems": []}

        packages = parse_files(self.files)
        dep_findings = match(packages, self.advisory_source)

        container_findings: List[Dict[str, Any]] = []
        for path, content in self.files.items():
            if _is_dockerfile(path):
                container_findings.extend(analyze_dockerfile(content or "", path))

        findings = dep_findings + container_findings
        paths = self._paths_for_critical(dep_findings)

        ecosystems = sorted({p.ecosystem for p in packages})
        logger.info("[sca] %s: %d packages, %d dep-vulns, %d container findings",
                    self.target, len(packages), len(dep_findings),
                    len(container_findings))
        return {
            "target": self.target,
            "packages": len(packages),
            "ecosystems": ecosystems,
            "findings": findings,
            "attack_paths": paths,
        }

    @staticmethod
    def _paths_for_critical(dep_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = []
        for f in dep_findings:
            if f.get("severity", "").upper() not in ("CRITICAL", "HIGH"):
                continue
            paths.append({
                "attack_path_id": str(uuid.uuid4()),
                "objective": f"Exploit vulnerable component {f['package']}",
                "starting_position": "internet",
                "target": f"component:{f['package']}",
                "severity": f["severity"],
                "steps": [{
                    "action": "exploit_known_cve",
                    "target": f["package"],
                    "precondition": f"{f['package']}=={f['installed_version']} "
                                    f"reachable ({f.get('cve') or f.get('advisory_id')})",
                    "tool": "public_exploit", "result": "code_execution",
                }],
                "techniques": ["ExploitPublicFacingApplication"],
                "evidence": f["proof"],
                "detection_confidence": 0.9,
                "exploit_confidence": 0.5,  # presence known; reachability not proven
                "status": "hypothesized",
                "source": "sca_attack_path",
            })
        return paths
