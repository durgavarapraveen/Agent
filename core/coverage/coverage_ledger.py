"""CoverageLedger — makes "what was tested" auditable so nothing skips silently.

The core failure mode of a scanner is the SILENT skip: a probe that errored,
was blocked, or was never reached looks identical in the output to a probe that
ran and found nothing. This ledger records, for every (surface, injection point,
vuln class) triple, exactly one terminal outcome:

  TESTED   — the probe actually executed and produced a verdict
  BLOCKED  — refused by policy/scope/WAF (recorded, not lost)
  ERRORED  — the probe raised; the error is captured, not swallowed
  SKIPPED  — deliberately not run (with a reason)

The report answers "did we test X?" honestly. It is the antidote to the
1600+ bare-except blocks: instead of hiding failures, we count them.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

TESTED = "TESTED"
BLOCKED = "BLOCKED"
ERRORED = "ERRORED"
SKIPPED = "SKIPPED"
_TERMINAL = (TESTED, BLOCKED, ERRORED, SKIPPED)


@dataclass
class LedgerEntry:
    surface: str
    point: str
    vuln_class: str
    status: str
    reason: str = ""
    confirmed: bool = False
    timestamp: float = field(default_factory=time.time)

    def key(self) -> str:
        return f"{self.surface}|{self.point}|{self.vuln_class}"


class CoverageLedger:
    def __init__(self, scan_id: str = "", target: str = ""):
        self._entries: Dict[str, LedgerEntry] = {}
        self._lock = threading.RLock()
        # When a scan_id is set, every terminal outcome is also written through
        # to the coverage_records DB table so coverage is durable/auditable and
        # can drive resumable planning across runs (spec §6/§20).
        self._scan_id = scan_id or ""
        self._target = target or ""

    def set_scan(self, scan_id: str, target: str = "") -> None:
        self._scan_id = scan_id or self._scan_id
        if target:
            self._target = target

    def _persist(self, e: LedgerEntry) -> None:
        if not self._scan_id:
            return
        loc, _, param = (e.point or "").partition(":")  # point == "location:name"
        try:
            from core.database.pg_store import CoverageRepo
            CoverageRepo.upsert(
                self._scan_id, e.surface or "", e.vuln_class or "",
                param=param or (e.point or ""), location=loc or "",
                status=(e.status or "").lower(), reason=e.reason,
                confirmed=e.confirmed, target=self._target)
        except Exception:
            pass  # persistence is best-effort; never breaks a scan

    def record(self, surface: str, point: str, vuln_class: str, status: str,
               reason: str = "", confirmed: bool = False) -> None:
        if status not in _TERMINAL:
            status = SKIPPED
        e = LedgerEntry(surface=surface, point=point, vuln_class=vuln_class,
                        status=status, reason=reason, confirmed=confirmed)
        with self._lock:
            # A confirmed TESTED result always wins; otherwise last write wins.
            prev = self._entries.get(e.key())
            if prev and prev.confirmed and not confirmed:
                return
            self._entries[e.key()] = e
        self._persist(e)
        if status in (ERRORED, BLOCKED):
            logger.info("COVERAGE_%s: %s @ %s [%s] %s", status, vuln_class, point, surface, reason)

    def tested(self, surface, point, vuln_class, confirmed=False):
        self.record(surface, point, vuln_class, TESTED, confirmed=confirmed)

    def errored(self, surface, point, vuln_class, reason):
        self.record(surface, point, vuln_class, ERRORED, reason=reason)

    def blocked(self, surface, point, vuln_class, reason):
        self.record(surface, point, vuln_class, BLOCKED, reason=reason)

    def skipped(self, surface, point, vuln_class, reason):
        self.record(surface, point, vuln_class, SKIPPED, reason=reason)

    # ── reporting ──────────────────────────────────────────────────────
    def counts(self) -> Dict[str, int]:
        with self._lock:
            c = Counter(e.status for e in self._entries.values())
        return {s: c.get(s, 0) for s in _TERMINAL}

    def gaps(self) -> List[LedgerEntry]:
        """Non-TESTED entries — the honest 'we did NOT verify these' list."""
        with self._lock:
            return [e for e in self._entries.values() if e.status != TESTED]

    def errors(self) -> List[LedgerEntry]:
        with self._lock:
            return [e for e in self._entries.values() if e.status == ERRORED]

    def completeness(self) -> float:
        with self._lock:
            total = len(self._entries)
            if not total:
                return 0.0
            done = sum(1 for e in self._entries.values() if e.status == TESTED)
        return done / total

    def report(self) -> Dict:
        counts = self.counts()
        errs = self.errors()
        return {
            "counts": counts,
            "completeness": round(self.completeness(), 4),
            "total_cells": sum(counts.values()),
            "errored_cells": [
                {"surface": e.surface, "point": e.point, "class": e.vuln_class, "reason": e.reason}
                for e in errs[:200]
            ],
            "blocked_count": counts.get(BLOCKED, 0),
            "skipped_count": counts.get(SKIPPED, 0),
        }
