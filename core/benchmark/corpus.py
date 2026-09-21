"""Generic benchmark corpus (spec §16-19) — benchmark-AGNOSTIC.

A "benchmark" here is any versioned set of challenges the scanner tries to solve
against a target. It is NOT tied to OWASP Juice Shop: a ``suite`` is just a name
(``juice-shop``, ``dvwa``, ``my-app``), and challenges can come from:

  * a **live challenge API** on the target (e.g. Juice Shop's ``/api/Challenges``),
    discovered and mapped generically — no hardcoded challenge list; or
  * a **static versioned corpus file** ``benchmarks/<suite>/<version>/challenges.json``
    for targets that don't expose one.

Scoring maps confirmed findings/coverage to challenges per-challenge (by id +
endpoint hint + technique), never by collapsing a whole vuln_class to one
"solved". Results carry explicit statuses + negative-evidence reasons and
run-level reproducibility metadata.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Benchmark result statuses (spec §18).
CONFIRMED = "confirmed"
PARTIAL = "partial"
NOT_FOUND = "not_found"
NOT_APPLICABLE = "not_applicable"
BLOCKED = "blocked"
ERROR = "error"

# Generic OWASP-category → canonical class map. Values are the SAME vocabulary
# as scripts/gap_analysis.JS_CLASSES so findings and challenges are compared in
# one taxonomy. Ordered longest-phrase-first at match time. Extend freely; this
# is generic security categorization, not application-specific.
_CATEGORY_TO_CLASS = {
    "broken access control": "broken_access_control",
    "access control": "broken_access_control",
    "authorization": "broken_access_control",
    "broken authentication": "broken_authentication",
    "authentication": "broken_authentication",
    "cryptographic": "cryptographic_issues", "crypto": "cryptographic_issues",
    "sensitive data": "sensitive_data_exposure",
    "information disclosure": "sensitive_data_exposure",
    "observability": "sensitive_data_exposure", "logging": "sensitive_data_exposure",
    "security misconfiguration": "security_misconfiguration",
    "misconfiguration": "security_misconfiguration",
    "security through obscurity": "security_misconfiguration",
    "obscurity": "security_misconfiguration",
    "improper input validation": "improper_input_validation",
    "input validation": "improper_input_validation",
    "insecure deserialization": "insecure_deserialization",
    "deserialization": "insecure_deserialization",
    "vulnerable components": "vulnerable_components",
    "components with known": "vulnerable_components", "components": "vulnerable_components",
    "unvalidated redirect": "unvalidated_redirect", "open redirect": "unvalidated_redirect",
    "broken anti automation": "broken_anti_automation", "anti automation": "broken_anti_automation",
    "prototype pollution": "prototype_pollution",
    "nosql": "injection_nosql",
    "cross site scripting": "xss", "cross-site scripting": "xss", "xss": "xss",
    "xxe": "xxe", "xml": "xxe",
    "ssrf": "ssrf", "csrf": "csrf",
    "injection": "injection_sql",   # generic default for the OWASP "Injection" category
}

# Checklist technique set = the canonical class vocabulary (gap_analysis).
_CHECKLIST_CLASSES = [
    "injection_sql", "injection_nosql", "injection_rce_cmd", "xss",
    "broken_access_control", "broken_authentication", "sensitive_data_exposure",
    "security_misconfiguration", "xxe", "ssrf", "unvalidated_redirect", "csrf",
    "insecure_deserialization", "broken_anti_automation", "improper_input_validation",
    "vulnerable_components", "cryptographic_issues", "prototype_pollution",
]


@dataclass
class Challenge:
    id: str
    name: str = ""
    category: str = ""
    source: str = ""                    # where it came from: live_api / static_file / ...
    description: str = ""
    difficulty: int = 0
    technique: str = ""                 # inferred vuln_class the challenge maps to
    target_hint: str = ""              # endpoint/path pattern if known ('' = unknown)
    prerequisites: List[str] = field(default_factory=list)  # e.g. authenticated_user, second_identity
    oracle_type: str = "generic"
    evidence_requirements: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkResult:
    challenge_id: str
    name: str = ""
    category: str = ""
    status: str = NOT_FOUND
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    requests: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    reason: str = ""
    duration_ms: int = 0
    corpus_version: str = ""
    run_meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def infer_technique(category: str, name: str = "", description: str = "") -> str:
    """Map an OWASP-ish category/name to a canonical class (gap_analysis vocab).
    Longest category phrase wins. Falls back to gap_analysis.classify() over the
    full text so name-driven items (e.g. a 'Login …' Injection challenge) still
    resolve. Generic — no application-specific rules."""
    blob = " ".join((category or "", name or "", description or "")).lower()
    for kw in sorted(_CATEGORY_TO_CLASS, key=len, reverse=True):
        if kw in blob:
            return _CATEGORY_TO_CLASS[kw]
    try:
        import scripts.gap_analysis as _ga
        cls = _ga.classify({"category": category, "name": name, "description": description})
        if cls:
            return sorted(cls)[0]
    except Exception:
        pass
    return ""


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "challenge"


class BenchmarkCorpus:
    """A versioned, benchmark-agnostic set of challenges."""

    def __init__(self, suite: str, version: str = "", challenges: Optional[List[Challenge]] = None):
        self.suite = suite
        self.version = version or datetime.now(timezone.utc).strftime("%Y%m%d")
        self.challenges: List[Challenge] = challenges or []

    # ── persistence ───────────────────────────────────────────────────────
    @staticmethod
    def _dir(suite: str, version: str) -> Path:
        root = os.getenv("BENCHMARK_CORPUS_DIR", "benchmarks")
        return Path(root) / suite / version

    def path(self) -> Path:
        return self._dir(self.suite, self.version) / "challenges.json"

    def save(self) -> str:
        p = self.path()
        p.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "suite": self.suite, "version": self.version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(self.challenges),
            "challenges": [c.to_dict() for c in self.challenges],
        }
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        logger.info("[BenchmarkCorpus] saved %s/%s (%d challenges) → %s",
                    self.suite, self.version, len(self.challenges), p)
        return str(p)

    @classmethod
    def load(cls, suite: str, version: str) -> Optional["BenchmarkCorpus"]:
        p = cls._dir(suite, version) / "challenges.json"
        try:
            with open(p, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            logger.debug("[BenchmarkCorpus] load %s failed: %s", p, e)
            return None
        chs = [Challenge(**{k: c.get(k) for k in Challenge.__annotations__ if k in c})
               for c in doc.get("challenges", [])]
        return cls(doc.get("suite", suite), doc.get("version", version), chs)

    @classmethod
    def latest_version(cls, suite: str) -> str:
        root = Path(os.getenv("BENCHMARK_CORPUS_DIR", "benchmarks")) / suite
        try:
            versions = sorted(d.name for d in root.iterdir() if d.is_dir())
            return versions[-1] if versions else ""
        except Exception:
            return ""
