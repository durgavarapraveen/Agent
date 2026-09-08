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
import time
from dataclasses import dataclass
from typing import Dict, List

logger = logging.getLogger(__name__)


from core.memory.database import DatabaseManager

NEW = "new"
RECURRING = "recurring"
RESOLVED = "resolved"


def generate_dedup_key(capability: str, target: str, resource: str = "") -> str:
    """
    Generate explicit deduplication key preserving exact target FQDN/subdomain.
    Format: {capability}:{exact_subdomain_or_target}:{port/resource}
    Example: port_scanning:millisecond.speshway.com:80
    """
    cap_clean = (capability or "").lower().strip()
    target_str = str(target or "").strip().lower()
    if "://" in target_str:
        target_str = target_str.split("://", 1)[1]
    if "/" in target_str:
        target_str = target_str.split("/", 1)[0]

    res_str = str(resource or "").strip().lower()
    if ":" in target_str and not res_str:
        parts = target_str.split(":", 1)
        target_str = parts[0]
        res_str = parts[1]

    return f"{cap_clean}:{target_str.strip()}:{res_str}"


def fingerprint(cve_id: str = "", file_path: str = "",
                function_name: str = "", package_version: str = "",
                target: str = "", title: str = "", vuln_type: str = "") -> str:
    """Stable SHA-256 fingerprint for a finding."""
    target_clean = (target or "").strip().lower()
    if "://" in target_clean:
        target_clean = target_clean.split("://", 1)[1]
    if "/" in target_clean:
        target_clean = target_clean.split("/", 1)[0]

    raw = "|".join([
        (cve_id or "").strip().upper(),
        (file_path or "").strip(),
        (function_name or "").strip(),
        (package_version or "").strip(),
        target_clean,
        (title or "").strip().lower(),
        (vuln_type or "").strip().upper(),
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
    """Tracks finding fingerprints across scans in PostgreSQL."""

    def __init__(self):
        self._init()

    def _init(self):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as c:
                c.execute(
                    "CREATE TABLE IF NOT EXISTS findings_history ("
                    "fingerprint TEXT PRIMARY KEY, cve_id TEXT, file_path TEXT, "
                    "function_name TEXT, package_version TEXT, severity TEXT, "
                    "first_seen REAL, last_seen REAL, last_scan_id TEXT, "
                    "status TEXT)")
                # Additive migration: `target` column scopes mark_resolved so that
                # scanning target B never marks target A's findings as resolved.
                c.execute(
                    "ALTER TABLE findings_history ADD COLUMN IF NOT EXISTS target TEXT")
                c.execute(
                    "CREATE INDEX IF NOT EXISTS idx_findings_history_target "
                    "ON findings_history(target)")
                conn.commit()

    @staticmethod
    def _normalize_target(target: str) -> str:
        t = (target or "").strip().lower()
        if "://" in t:
            t = t.split("://", 1)[1]
        if "/" in t:
            t = t.split("/", 1)[0]
        return t

    def classify(self, finding: Dict, scan_id: str) -> DedupResult:
        """Classify one finding for the current scan and update history."""
        target_val = finding.get("target") or finding.get("host") or finding.get("domain") or ""
        target_norm = self._normalize_target(target_val)
        title_val = finding.get("title") or finding.get("name") or ""
        type_val = finding.get("type") or finding.get("vuln_type") or ""
        fp = fingerprint(
            finding.get("cve_id", ""), finding.get("file_path", finding.get("location", "")),
            finding.get("function_name", ""), finding.get("package_version", ""),
            target=target_val, title=title_val, vuln_type=type_val)
        severity = str(finding.get("severity", "")).upper()
        now = time.time()

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as c:
                c.execute(
                    "SELECT severity, first_seen FROM findings_history WHERE fingerprint=%s",
                    (fp,))
                row = c.fetchone()

                if row is None:
                    c.execute(
                        "INSERT INTO findings_history(fingerprint, cve_id, file_path, "
                        "function_name, package_version, severity, first_seen, last_seen, "
                        "last_scan_id, status, target) "
                        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (fp, finding.get("cve_id", ""),
                         finding.get("file_path", finding.get("location", "")),
                         finding.get("function_name", ""),
                         finding.get("package_version", ""),
                         severity, now, now, scan_id, NEW, target_norm))
                    conn.commit()
                    return DedupResult(fp, NEW, severity, "", False, False, now, now)

                prev_sev = str(row[0] or "").upper()
                first_seen = row[1] or now
                changed = prev_sev != severity
                c.execute(
                    "UPDATE findings_history SET severity=%s, last_seen=%s, "
                    "last_scan_id=%s, status=%s, target=COALESCE(NULLIF(target,''),%s) "
                    "WHERE fingerprint=%s",
                    (severity, now, scan_id, RECURRING, target_norm, fp))
                conn.commit()
                return DedupResult(
                    fp, RECURRING, severity, prev_sev, changed,
                    suppressed=not changed, first_seen=first_seen, last_seen=now)

    def mark_resolved(self, scan_id: str, target: str = None) -> List[str]:
        """Findings not seen in this scan_id are resolved. Scoped by target so
        that a scan against target B does NOT mark target A's findings as resolved.

        `target` MUST be supplied when there are historical findings for other
        targets in the DB. If it is None, we log a warning and skip the sweep
        rather than performing a dangerous global mark.
        """
        if not target:
            logger.warning(
                "mark_resolved called without target; skipping to avoid cross-target "
                "contamination. Pass target explicitly.")
            return []
        target_norm = self._normalize_target(target)
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as c:
                c.execute(
                    "SELECT fingerprint FROM findings_history "
                    "WHERE last_scan_id != %s AND status != %s AND target = %s",
                    (scan_id, RESOLVED, target_norm))
                rows = c.fetchall()
                fps = [r[0] for r in rows]
                if fps:
                    c.execute(
                        "UPDATE findings_history SET status=%s "
                        "WHERE fingerprint = ANY(%s)",
                        (RESOLVED, fps))
                    conn.commit()
        return fps

    def process_scan(self, findings: List[Dict], scan_id: str,
                     include_recurring: bool = False, target: str = None) -> Dict:
        """Classify a full scan's findings and compute resolved set.

        Returns {'results': [DedupResult...], 'report': [findings kept],
                 'suppressed_findings': [suppressed findings],
                 'suppressed': N, 'resolved': [fingerprints]}.

        If include_recurring=True, recurring findings are still included in the
        report (marked as recurring) instead of being suppressed.
        """
        results, report, suppressed_findings = [], [], []
        suppressed = 0
        for f in findings:
            res = self.classify(f, scan_id)
            results.append(res)
            f["_dedup"] = res.to_dict()
            title = f.get("title") or f.get("name") or f.get("type") or "unnamed finding"
            loc = f.get("file_path") or f.get("location") or f.get("url") or ""
            sev = (res.severity or "").upper()
            # Never suppress recurring HIGH/CRITICAL even when their severity
            # hasn't changed. A HIGH SQLi that's still exploitable in the
            # current scan must appear in the current report — silently
            # suppressing it was the source of "the report says everything is
            # fine but the vuln is still there" incidents (#104).
            force_include = sev in ("CRITICAL", "HIGH")
            if res.suppressed and not include_recurring and not force_include:
                suppressed += 1
                suppressed_findings.append(f)
                logger.info(f"DEDUP_ACTION: status=RECURRING_SUPPRESSED title='{title}' location='{loc}' fingerprint={res.fingerprint} severity={res.severity} reason='Finding already recorded in prior scan with identical severity'")
            else:
                report.append(f)
                if res.suppressed and force_include:
                    logger.info(f"DEDUP_ACTION: status=RECURRING_KEPT_HIGH_SEV title='{title}' location='{loc}' fingerprint={res.fingerprint} severity={res.severity}")
                elif res.suppressed:
                    logger.info(f"DEDUP_ACTION: status=RECURRING_INCLUDED title='{title}' location='{loc}' fingerprint={res.fingerprint} severity={res.severity}")
                else:
                    logger.info(f"DEDUP_ACTION: status={res.status} title='{title}' location='{loc}' fingerprint={res.fingerprint} severity={res.severity}")
        # If target not passed explicitly, infer from the first finding that carries
        # one. This preserves backward compatibility for callers that don't yet pass
        # target while keeping the safety property: mark_resolved refuses to run
        # without a target.
        target_for_sweep = target
        if not target_for_sweep:
            for f in findings:
                t = f.get("target") or f.get("host") or f.get("domain")
                if t:
                    target_for_sweep = t
                    break
        resolved = self.mark_resolved(scan_id, target=target_for_sweep)
        return {"results": results, "report": report,
                "suppressed_findings": suppressed_findings,
                "suppressed": suppressed, "resolved": resolved}
