"""
Baseline Normalization Module (Phase 4 Module 4.3).
Captures baseline state (first scan mode), filters known-good noise, respects whitelist overrides,
hashes responses (SHA-256), and detects baseline drift (>20% deviation).
"""

import hashlib
import json
import logging
import os
import sqlite3
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

WHITELIST_FILE = "whitelist.json"


def sha256_hash(data: str) -> str:
    """Generate SHA-256 hash string for response data."""
    if not data:
        return ""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


class BaselineManager:
    """Manages baseline capture, noise filtering, whitelist matching, and drift detection."""

    def __init__(self, db_path: str = "baseline_store.sqlite", whitelist_file: str = WHITELIST_FILE):
        if not os.path.exists(db_path) and os.path.exists(os.path.join("data", db_path)):
            db_path = os.path.join("data", db_path)
        if not os.path.exists(whitelist_file) and os.path.exists(os.path.join("data", whitelist_file)):
            whitelist_file = os.path.join("data", whitelist_file)
        self.db_path = db_path
        self.whitelist_file = whitelist_file
        self._init_db()
        self.whitelist = self._load_whitelist()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS baseline_state (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        target TEXT,
                        item_type TEXT,
                        key_identifier TEXT,
                        banner_hash TEXT,
                        content_length_hash TEXT,
                        header_hash TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"[BaselineManager] DB init error: {e}")

    def _load_whitelist(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.whitelist_file):
            try:
                with open(self.whitelist_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.debug(f"[BaselineManager] Whitelist load error: {e}")
        return []

    def is_whitelisted(self, finding: Dict[str, Any]) -> bool:
        """Check if finding matches whitelist.json entries."""
        port = finding.get("port")
        url = finding.get("url") or finding.get("target")

        for w in self.whitelist:
            if port is not None and w.get("port") == port:
                logger.info(f"[BaselineManager] Finding port {port} excluded by whitelist (Reason: {w.get('reason')})")
                return True
            if url and w.get("url") and w.get("url").lower() in str(url).lower():
                logger.info(f"[BaselineManager] Finding URL {url} excluded by whitelist (Reason: {w.get('reason')})")
                return True
        return False

    def capture_baseline(self, scan_id: str, target: str, findings: List[Dict[str, Any]]) -> int:
        """First Scan Mode: Capture baseline state and store response hashes into SQLite table baseline_state."""
        captured_count = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                for f in findings:
                    item_type = f.get("type", "generic")
                    key_id = str(f.get("port") or f.get("url") or f.get("cve_id") or f.get("title"))
                    b_hash = sha256_hash(str(f.get("banner") or ""))
                    l_hash = sha256_hash(str(f.get("content_length") or f.get("response_length") or ""))
                    h_hash = sha256_hash(str(f.get("headers") or f.get("status_code") or ""))

                    conn.execute("""
                        INSERT INTO baseline_state (scan_id, target, item_type, key_identifier, banner_hash, content_length_hash, header_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (scan_id, target, item_type, key_id, b_hash, l_hash, h_hash))
                    captured_count += 1
                conn.commit()
            logger.info(f"[BaselineManager] First scan mode: captured {captured_count} baseline records for scan '{scan_id}'")
        except Exception as e:
            logger.error(f"[BaselineManager] Capture baseline error: {e}")

        return captured_count

    def filter_noise_and_detect_drift(self, target: str, current_findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Subsequent Scans: Filter out known baseline noise and whitelist entries.
        Triggers DRIFT_ALERT if new changes deviate by >20% from baseline count.
        """
        # Load baseline records for target
        baseline_records = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT key_identifier, banner_hash, content_length_hash, header_hash FROM baseline_state WHERE target=?", (target,))
                for row in cur.fetchall():
                    baseline_records[row[0]] = {
                        "banner_hash": row[1],
                        "content_length_hash": row[2],
                        "header_hash": row[3]
                    }
        except Exception as e:
            logger.debug(f"[BaselineManager] Reading baseline error: {e}")

        filtered_findings = []
        noise_count = 0
        new_changes_count = 0

        for f in current_findings:
            # 1. Whitelist Check
            if self.is_whitelisted(f):
                noise_count += 1
                continue

            key_id = str(f.get("port") or f.get("url") or f.get("cve_id") or f.get("title"))
            b_hash = sha256_hash(str(f.get("banner") or ""))
            l_hash = sha256_hash(str(f.get("content_length") or f.get("response_length") or ""))
            h_hash = sha256_hash(str(f.get("headers") or f.get("status_code") or ""))

            # 2. Exact Baseline Match Check
            if key_id in baseline_records:
                base = baseline_records[key_id]
                if (base["banner_hash"] == b_hash and base["content_length_hash"] == l_hash and base["header_hash"] == h_hash):
                    logger.info(f"[BaselineManager] Excluding noise finding '{key_id}' matching baseline state")
                    noise_count += 1
                    continue

            # Deviation or New Change
            filtered_findings.append(f)
            new_changes_count += 1

        # Drift Detection Alert Calculation
        baseline_total = len(baseline_records)
        drift_ratio = (new_changes_count / float(baseline_total)) if baseline_total > 0 else 0.0
        drift_alert = False
        drift_msg = ""

        if drift_ratio > 0.20:
            drift_alert = True
            drift_msg = f"[DRIFT_ALERT] Baseline drift detected! Target '{target}' changed by {round(drift_ratio * 100, 1)}% ({new_changes_count} new/deviated items vs {baseline_total} baseline items). Please verify if these changes are authorized."
            logger.warning(drift_msg)
            print(f"=== DRIFT ALERT ===\n{drift_msg}\n===================")

        stats = {
            "baseline_total": baseline_total,
            "noise_filtered": noise_count,
            "new_changes": new_changes_count,
            "drift_ratio": round(drift_ratio, 2),
            "drift_alert": drift_alert,
            "drift_message": drift_msg
        }

        return filtered_findings, stats
