"""
Deduplication Tracker for Repeated Tasks.
Tracks findings by SHA-256 signature in SQLite, detects delta updates between runs,
and prevents re-sending duplicate data across multiple agent execution steps.
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DeduplicationTracker:
    """Thread-safe SQLite-backed deduplication tracker for findings and assets."""

    def __init__(self, db_path: str = "reports/findings_dedup.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings_dedup (
                        signature TEXT PRIMARY KEY,
                        tool TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        data_repr TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        count INTEGER DEFAULT 1,
                        task_id TEXT
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def generate_signature(self, tool: str, finding_type: str, data: Any) -> str:
        """Generate SHA-256 fingerprint signature: tool:finding_type:sha256(data)"""
        tool_clean = (tool or "").lower().strip()
        type_clean = (finding_type or "").lower().strip()
        
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True, default=str)
        else:
            data_str = str(data).strip().lower()

        data_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
        return f"{tool_clean}:{type_clean}:{data_hash}"

    def is_duplicate(self, tool: str, finding_type: str, data: Any) -> bool:
        """Check if finding signature already exists in deduplication database."""
        sig = self.generate_signature(tool, finding_type, data)
        with self._lock:
            conn = self._get_connection()
            try:
                row = conn.execute("SELECT 1 FROM findings_dedup WHERE signature = ?", (sig,)).fetchone()
                return row is not None
            finally:
                conn.close()

    def register_finding(self, tool: str, finding_type: str, data: Any, task_id: str = "") -> str:
        """Register a finding. If signature exists, update last_seen and count; otherwise insert new."""
        sig = self.generate_signature(tool, finding_type, data)
        now = datetime.now().isoformat()
        data_repr = str(data)[:300]

        with self._lock:
            conn = self._get_connection()
            try:
                row = conn.execute("SELECT count FROM findings_dedup WHERE signature = ?", (sig,)).fetchone()
                if row:
                    new_count = row["count"] + 1
                    conn.execute("""
                        UPDATE findings_dedup 
                        SET last_seen = ?, count = ?, task_id = ?
                        WHERE signature = ?
                    """, (now, new_count, task_id, sig))
                else:
                    conn.execute("""
                        INSERT INTO findings_dedup (signature, tool, finding_type, data_repr, first_seen, last_seen, count, task_id)
                        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """, (sig, tool, finding_type, data_repr, now, now, task_id))
                conn.commit()
            finally:
                conn.close()
        return sig

    def get_delta(self, tool: str, finding_type: str, new_data: List[Any], task_id: str = "") -> Dict[str, Any]:
        """
        Calculate delta between new findings and previously registered findings.
        Registers new findings into the database.
        Returns dict containing new_items, known_items, counts, and formatted summary string.
        """
        tool_clean = (tool or "").lower().strip()
        type_clean = (finding_type or "").lower().strip()
        
        new_items = []
        known_items = []

        for item in new_data:
            if self.is_duplicate(tool_clean, type_clean, item):
                known_items.append(item)
            else:
                new_items.append(item)
                self.register_finding(tool_clean, type_clean, item, task_id=task_id)

        total_count = len(new_data)
        new_count = len(new_items)
        known_count = len(known_items)

        formatted_summary = self.format_delta_summary(
            tool=tool_clean,
            total_count=total_count,
            new_items=new_items,
            known_count=known_count,
            task_id=task_id
        )

        return {
            "new_items": new_items,
            "known_items": known_items,
            "total_count": total_count,
            "new_count": new_count,
            "known_count": known_count,
            "formatted_summary": formatted_summary
        }

    def format_delta_summary(
        self,
        tool: str,
        total_count: int,
        new_items: List[Any],
        known_count: int,
        task_id: str = ""
    ) -> str:
        """Format delta analysis into canonical update string."""
        sample_str = ", ".join([str(x) for x in new_items[:3]]) if new_items else "none"
        prev_task = task_id if task_id else "previous_task"
        
        lines = [
            f"TOOL_RESULT: {tool}",
            f"Status: SUCCESS (update)",
            f"Total findings: {total_count}",
            f"New findings: +{len(new_items)} ({sample_str})",
            f"Previous findings: {known_count} (stable)",
            f"Previous task: {prev_task}"
        ]
        return "\n".join(lines)

    def clear_cache(self, hours: int = 24) -> int:
        """Purge entries older than specified hours."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("DELETE FROM findings_dedup WHERE last_seen < ?", (cutoff,))
                deleted = cur.rowcount
                conn.commit()
                logger.info(f"DEDUP_CACHE_PURGED: removed {deleted} entries older than {hours}h")
                return deleted
            finally:
                conn.close()

    def reset_all(self) -> None:
        """Clear all deduplication records from the database."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM findings_dedup")
                conn.commit()
                logger.info("DEDUP_CACHE_RESET: cleared all deduplication entries")
            finally:
                conn.close()
