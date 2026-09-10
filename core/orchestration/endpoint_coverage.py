from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from time import time
from typing import Dict, List, Optional, Set


@dataclass
class CoverageRecord:
    endpoint: str
    method: str
    auth_state: str = "anonymous"
    parameters: List[str] = field(default_factory=list)
    tested_classes: Dict[str, Dict] = field(default_factory=dict)
    # tested_classes = {"sqli": {"tested_at": t, "result": "negative"|"positive"|"inconclusive", "confidence": 0..1}}

    def mark(self, vuln_class: str, result: str, confidence: float = 0.5) -> None:
        self.tested_classes[vuln_class.lower()] = {
            "tested_at": time(), "result": result, "confidence": confidence,
        }

    def has_tested(self, vuln_class: str) -> bool:
        return vuln_class.lower() in self.tested_classes

    def gaps(self, universe: List[str]) -> List[str]:
        return [c for c in universe if c.lower() not in self.tested_classes]


class CoverageTracker:
    def __init__(self):
        self._records: Dict[str, CoverageRecord] = {}
        self._lock = Lock()

    @staticmethod
    def _key(endpoint: str, method: str, auth_state: str) -> str:
        return f"{(method or 'GET').upper()} {endpoint} [{auth_state}]"

    def upsert(self, endpoint: str, method: str = "GET",
               auth_state: str = "anonymous",
               parameters: Optional[List[str]] = None) -> CoverageRecord:
        with self._lock:
            k = self._key(endpoint, method, auth_state)
            r = self._records.get(k)
            if r is None:
                r = CoverageRecord(endpoint=endpoint, method=(method or "GET").upper(),
                                   auth_state=auth_state, parameters=list(parameters or []))
                self._records[k] = r
            else:
                for p in (parameters or []):
                    if p not in r.parameters:
                        r.parameters.append(p)
            return r

    def mark(self, endpoint: str, vuln_class: str, result: str,
             method: str = "GET", auth_state: str = "anonymous",
             confidence: float = 0.5) -> None:
        r = self.upsert(endpoint, method, auth_state)
        r.mark(vuln_class, result, confidence)

    def gaps_for(self, endpoint: str, universe: List[str],
                 method: str = "GET", auth_state: str = "anonymous") -> List[str]:
        r = self.upsert(endpoint, method, auth_state)
        return r.gaps(universe)

    def summary(self) -> Dict[str, int]:
        with self._lock:
            covered = sum(1 for r in self._records.values() if r.tested_classes)
            return {"endpoints": len(self._records), "covered": covered,
                    "uncovered": len(self._records) - covered}


_SINGLETON: Optional[CoverageTracker] = None


def get_coverage() -> CoverageTracker:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = CoverageTracker()
    return _SINGLETON
