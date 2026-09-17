
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
    status: str
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
        target_val = finding.get("target") or finding.get("host") or finding.get("domain") or ""
        target_norm = self._normalize_target(target_val)
        title_val = finding.get("title") or finding.get("name") or ""
        type_val = finding.get("type") or finding.get("vuln_type") or ""
        loc_val = finding.get("file_path") or finding.get("location") or finding.get("url") or ""
        cve_val = finding.get("cve_id", "")
        # Collision guard: if EVERY discriminating field is empty, fingerprint()
        # would collapse to a constant hash and merge unrelated findings. Fall
        # back to hashing the whole finding so distinct ones stay distinct.
        if not any([cve_val, loc_val, title_val, type_val, target_val,
                    finding.get("function_name"), finding.get("package_version")]):
            import json as _json
            fp = hashlib.sha256(
                _json.dumps(finding, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        else:
            fp = fingerprint(
                cve_val, finding.get("file_path", finding.get("location", "")),
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
                is_new = row is None
                # Atomic upsert — avoids a PRIMARY KEY violation when two
                # concurrent scans classify the same fingerprint at once.
                c.execute(
                    "INSERT INTO findings_history(fingerprint, cve_id, file_path, "
                    "function_name, package_version, severity, first_seen, last_seen, "
                    "last_scan_id, status, target) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT(fingerprint) DO UPDATE SET "
                    "severity=EXCLUDED.severity, last_seen=EXCLUDED.last_seen, "
                    "last_scan_id=EXCLUDED.last_scan_id, status=%s, "
                    "target=COALESCE(NULLIF(findings_history.target,''), EXCLUDED.target)",
                    (fp, cve_val, finding.get("file_path", finding.get("location", "")),
                     finding.get("function_name", ""), finding.get("package_version", ""),
                     severity, now, now, scan_id, (NEW if is_new else RECURRING), target_norm,
                     RECURRING))
                conn.commit()

                if is_new:
                    return DedupResult(fp, NEW, severity, "", False, False, now, now)
                prev_sev = str(row[0] or "").upper()
                first_seen = row[1] or now
                changed = prev_sev != severity
                return DedupResult(
                    fp, RECURRING, severity, prev_sev, changed,
                    suppressed=not changed, first_seen=first_seen, last_seen=now)

    def mark_resolved(self, scan_id: str, target: str = None) -> List[str]:
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
                     include_recurring: bool = False, target: str = None,
                     full_scan: bool = False) -> Dict:
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
        # Only auto-resolve prior findings on a FULL scan. A partial/incremental
        # scan does not re-test every endpoint, so sweeping would silently mark
        # still-present vulns as resolved just because they weren't re-run.
        resolved: List[str] = []
        if full_scan:
            target_for_sweep = target
            if not target_for_sweep:
                for f in findings:
                    t = f.get("target") or f.get("host") or f.get("domain")
                    if t:
                        target_for_sweep = t
                        break
            resolved = self.mark_resolved(scan_id, target=target_for_sweep)
        else:
            logger.debug("process_scan: full_scan=False; skipping resolve sweep "
                         "(partial coverage must not auto-close findings)")
        return {"results": results, "report": report,
                "suppressed_findings": suppressed_findings,
                "suppressed": suppressed, "resolved": resolved}
