"""Recall harness — measures how much the agent actually finds.

You cannot claim "finds everything" without a number. This scores a scan's
findings against a catalog of KNOWN vulnerabilities (Juice Shop challenges,
DVWA cases, or any labeled corpus) and produces:

  recall     = known vulns detected / total known
  precision  = confirmed findings that map to a known vuln / all confirmed
  miss_list  = the known vulns we did NOT find (the prioritized to-do)

Class-normalized so a finding of type "sql_injection" matches a challenge whose
class is "SQLI". Offline/pure — feed it findings + a catalog from anywhere.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

logger = logging.getLogger(__name__)


def _norm_class(s: str) -> str:
    s = (s or "").strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "SQL_INJECTION": "SQLI", "SQLINJECTION": "SQLI",
        "CROSS_SITE_SCRIPTING": "XSS", "REFLECTED_XSS": "XSS", "STORED_XSS": "XSS", "DOM_XSS": "XSS",
        "COMMAND_INJECTION": "RCE", "OS_COMMAND_INJECTION": "RCE", "CODE_INJECTION": "RCE",
        "BROKEN_ACCESS_CONTROL": "ACCESS_CONTROL", "BOLA": "IDOR", "BFLA": "ACCESS_CONTROL",
        "SENSITIVE_DATA_EXPOSURE": "INFORMATION_DISCLOSURE", "INFO_LEAK": "INFORMATION_DISCLOSURE",
        "SSTI_INJECTION": "SSTI", "PATH_TRAVERSAL": "LFI", "FILE_INCLUSION": "LFI",
        "OPEN_REDIRECTION": "OPEN_REDIRECT", "JWT_MANIPULATION": "JWT",
    }
    return aliases.get(s, s)


@dataclass
class KnownVuln:
    id: str
    vuln_class: str
    category: str = ""
    title: str = ""

    @property
    def nclass(self) -> str:
        return _norm_class(self.vuln_class)


@dataclass
class RecallReport:
    total_known: int
    detected: int
    recall: float
    precision: float
    by_class: Dict[str, Dict[str, int]] = field(default_factory=dict)
    miss_list: List[Dict[str, str]] = field(default_factory=list)
    matched_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_known": self.total_known, "detected": self.detected,
            "recall": round(self.recall, 4), "precision": round(self.precision, 4),
            "by_class": self.by_class, "miss_list": self.miss_list,
            "matched_ids": self.matched_ids,
        }


def score(findings: Iterable[Dict[str, Any]], catalog: Iterable[KnownVuln],
          confirmed_only: bool = False) -> RecallReport:
    catalog = list(catalog)
    known_by_class: Dict[str, List[KnownVuln]] = {}
    for kv in catalog:
        known_by_class.setdefault(kv.nclass, []).append(kv)

    found_classes: Set[str] = set()
    confirmed_count = 0
    for f in findings:
        if confirmed_only and not f.get("confirmed"):
            continue
        if f.get("confirmed"):
            confirmed_count += 1
        cls = _norm_class(f.get("type") or f.get("vuln_class") or f.get("vuln_type") or "")
        if cls:
            found_classes.add(cls)

    matched_ids: List[str] = []
    by_class: Dict[str, Dict[str, int]] = {}
    miss_list: List[Dict[str, str]] = []
    for ncls, kvs in known_by_class.items():
        hit = ncls in found_classes
        by_class[ncls] = {"known": len(kvs), "detected": len(kvs) if hit else 0}
        for kv in kvs:
            if hit:
                matched_ids.append(kv.id)
            else:
                miss_list.append({"id": kv.id, "class": kv.nclass,
                                  "category": kv.category, "title": kv.title})

    total = len(catalog)
    detected = len(matched_ids)
    recall = detected / total if total else 0.0
    # precision: confirmed findings whose class maps to a known vuln class
    mapped = sum(1 for f in findings
                 if f.get("confirmed") and _norm_class(f.get("type") or f.get("vuln_class") or "") in known_by_class)
    precision = (mapped / confirmed_count) if confirmed_count else 0.0
    return RecallReport(total, detected, recall, precision, by_class, miss_list, matched_ids)


# ── catalog loaders ────────────────────────────────────────────────────
def juice_shop_catalog() -> List[KnownVuln]:
    from tests.benchmarks.juice_shop_benchmark import JUICE_SHOP_CHALLENGES
    return [KnownVuln(id=c.id, vuln_class=c.vuln_class,
                      category=getattr(c, "category", ""), title=getattr(c, "name", getattr(c, "title", "")))
            for c in JUICE_SHOP_CHALLENGES]


def dvwa_catalog() -> List[KnownVuln]:
    from tests.benchmarks.dvwa_benchmark import DVWA_CASES
    out = []
    for c in DVWA_CASES:
        out.append(KnownVuln(
            id=getattr(c, "id", getattr(c, "case_id", str(id(c)))),
            vuln_class=getattr(c, "vuln_class", getattr(c, "category", "")),
            category=getattr(c, "category", ""), title=getattr(c, "name", "")))
    return out
