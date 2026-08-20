"""
Finding deduplication across scan runs.

Each finding is fingerprinted as
    sha256(cve_id + file_path + function_name + package_version)
and tracked in a SQLite `findings_history` table. On each scan a finding is
classified as:
  - new        : fingerprint never seen before
  - recurring  : seen in a previous scan and still present
  - resolved   : previously seen but absent from the current scan

Recurring findings are suppressed from the main report UNLESS their severity
changed since last seen (a regression/escalation worth surfacing).
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@contextmanager
def _connect(path: str):
    """sqlite connection that actually CLOSES on exit.

    `with sqlite3.connect(...)` only commits/rolls back — it leaves the handle
    open, which locks the file on Windows. This wrapper commits and closes.
    """
    conn = sqlite3.connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

NEW = "new"
RECURRING = "recurring"
RESOLVED = "resolved"

DEFAULT_DB = ".findings_history.sqlite"


def fingerprint(cve_id: str = "", file_path: str = "",
                function_name: str = "", package_version: str = "") -> str:
    """Stable SHA-256 fingerprint for a finding."""
    raw = "|".join([
        (cve_id or "").strip().upper(),
        (file_path or "").strip(),
        (function_name or "").strip(),
        (package_version or "").strip(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class DedupResult:
    fingerprint: str
    status: str                  # new | recurring | resolved
    severity: str = ""
    prev_severity: str = ""
    severity_changed: bool = False
    suppressed: bool = False     # True when recurring + severity unchanged
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "fingerprint": self.fingerprint, "status": self.status,
            "severity": self.severity, "prev_severity": self.prev_severity,
            "severity_changed": self.severity_changed,
            "suppressed": self.suppressed,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }


class DedupStore:
    """Tracks finding fingerprints across scans in SQLite."""

    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        self._init()

    def _init(self):
        with _connect(self.db_path) as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS findings_history ("
                "fingerprint TEXT PRIMARY KEY, cve_id TEXT, file_path TEXT, "
                "function_name TEXT, package_version TEXT, severity TEXT, "
                "first_seen REAL, last_seen REAL, last_scan_id TEXT, "
                "status TEXT)")
            c.commit()

    def classify(self, finding: Dict, scan_id: str) -> DedupResult:
        """Classify one finding for the current scan and update history."""
        fp = fingerprint(
            finding.get("cve_id", ""), finding.get("file_path", finding.get("location", "")),
            finding.get("function_name", ""), finding.get("package_version", ""))
        severity = str(finding.get("severity", "")).upper()
        now = time.time()

        with _connect(self.db_path) as c:
            row = c.execute(
                "SELECT severity, first_seen FROM findings_history WHERE fingerprint=?",
                (fp,)).fetchone()

            if row is None:
                c.execute(
                    "INSERT INTO findings_history(fingerprint, cve_id, file_path, "
                    "function_name, package_version, severity, first_seen, last_seen, "
                    "last_scan_id, status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (fp, finding.get("cve_id", ""),
                     finding.get("file_path", finding.get("location", "")),
                     finding.get("function_name", ""),
                     finding.get("package_version", ""),
                     severity, now, now, scan_id, NEW))
                c.commit()
                return DedupResult(fp, NEW, severity, "", False, False, now, now)

            prev_sev = str(row[0] or "").upper()
            first_seen = row[1] or now
            changed = prev_sev != severity
            c.execute(
                "UPDATE findings_history SET severity=?, last_seen=?, "
                "last_scan_id=?, status=? WHERE fingerprint=?",
                (severity, now, scan_id, RECURRING, fp))
            c.commit()
            return DedupResult(
                fp, RECURRING, severity, prev_sev, changed,
                suppressed=not changed, first_seen=first_seen, last_seen=now)

    def mark_resolved(self, scan_id: str) -> List[str]:
        """Findings not seen in this scan_id are resolved. Returns their fingerprints."""
        with _connect(self.db_path) as c:
            rows = c.execute(
                "SELECT fingerprint FROM findings_history "
                "WHERE last_scan_id != ? AND status != ?",
                (scan_id, RESOLVED)).fetchall()
            fps = [r[0] for r in rows]
            if fps:
                c.executemany(
                    "UPDATE findings_history SET status=? WHERE fingerprint=?",
                    [(RESOLVED, fp) for fp in fps])
                c.commit()
        return fps

    def process_scan(self, findings: List[Dict], scan_id: str) -> Dict:
        """Classify a full scan's findings and compute resolved set.

        Returns {'results': [DedupResult...], 'report': [findings kept],
                 'suppressed': N, 'resolved': [fingerprints]}.
        """
        results, report = [], []
        suppressed = 0
        for f in findings:
            res = self.classify(f, scan_id)
            results.append(res)
            f["_dedup"] = res.to_dict()
            if res.suppressed:
                suppressed += 1
            else:
                report.append(f)
        resolved = self.mark_resolved(scan_id)
        return {"results": results, "report": report,
                "suppressed": suppressed, "resolved": resolved}
