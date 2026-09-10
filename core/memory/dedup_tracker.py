
import hashlib
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)


class DeduplicationTracker:

    def __init__(self):
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'findings_dedup')"
                    )
                    exists = cur.fetchone()[0]
                    if not exists:
                        logger.warning("findings_dedup table does not exist — expected pg_store.py to create it")

    def generate_task_key(self, capability: str, target: str, resource: str = "") -> str:
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

        target_clean = target_str.strip()

        return f"{cap_clean}:{target_clean}:{res_str}"

    def generate_signature(self, tool: str, finding_type: str, data: Any) -> str:
        tool_clean = (tool or "").lower().strip()
        type_clean = (finding_type or "").lower().strip()

        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True, default=str)
        else:
            data_str = str(data).strip().lower()

        data_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
        return f"{tool_clean}:{type_clean}:{data_hash}"

    def is_duplicate(self, tool: str, finding_type: str, data: Any) -> bool:
        sig = self.generate_signature(tool, finding_type, data)
        with self._lock:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM findings_dedup WHERE signature = %s", (sig,))
                    row = cur.fetchone()
                    return row is not None

    def register_finding(self, tool: str, finding_type: str, data: Any, task_id: str = "") -> str:
        sig = self.generate_signature(tool, finding_type, data)
        now = datetime.now().isoformat()
        data_repr = str(data)[:300]

        with self._lock:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT count FROM findings_dedup WHERE signature = %s", (sig,))
                    row = cur.fetchone()
                    if row:
                        new_count = row["count"] + 1
                        cur.execute("""
                            UPDATE findings_dedup
                            SET last_seen = %s, count = %s, task_id = %s
                            WHERE signature = %s
                        """, (now, new_count, task_id, sig))
                    else:
                        cur.execute("""
                            INSERT INTO findings_dedup (signature, tool, finding_type, data_repr, first_seen, last_seen, count, task_id)
                            VALUES (%s, %s, %s, %s, %s, %s, 1, %s)
                        """, (sig, tool, finding_type, data_repr, now, now, task_id))
                    conn.commit()
        return sig

    def get_delta(self, tool: str, finding_type: str, new_data: List[Any], task_id: str = "") -> Dict[str, Any]:
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
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM findings_dedup WHERE last_seen < %s", (cutoff,))
                    deleted = cur.rowcount
                    conn.commit()
                    logger.info(f"DEDUP_CACHE_PURGED: removed {deleted} entries older than {hours}h")
                    return deleted

    def reset_all(self) -> None:
        with self._lock:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM findings_dedup")
                    conn.commit()


from dataclasses import dataclass
from typing import Set, Optional

@dataclass(frozen=True)
class TaskRecord:
    task_hash: str
    task_id: str
    capability: str
    target: str

class DedupTracker:
    
    def __init__(self):
        self._lock = threading.RLock()
        self._active_tasks: Dict[str, TaskRecord] = {}
        self._completed_tasks: Dict[str, TaskRecord] = {}
        self._failed_tasks: Set[str] = set()
        self._permanent_failures: Set[str] = set()

    def get_task_hash(self, capability: str, target: str, params: dict) -> str:
        data = f"{capability}:{target}:{json.dumps(params, sort_keys=True)}"
        return hashlib.sha256(data.encode()).hexdigest()

    def register_task(self, task_hash: str, task_id: str, capability: str = "", target: str = "") -> Optional[str]:
        with self._lock:
            if task_hash in self._completed_tasks:
                return self._completed_tasks[task_hash].task_id
            if task_hash in self._active_tasks:
                return self._active_tasks[task_hash].task_id
                
            self._active_tasks[task_hash] = TaskRecord(
                task_hash=task_hash, 
                task_id=task_id, 
                capability=capability, 
                target=target
            )
            return None

    def mark_completed(self, task_hash: str):
        with self._lock:
            if task_hash in self._active_tasks:
                record = self._active_tasks.pop(task_hash)
                self._completed_tasks[task_hash] = record
                
    def mark_failed(self, task_hash: str, permanent: bool = False):
        with self._lock:
            if task_hash in self._active_tasks:
                self._active_tasks.pop(task_hash)
            
            if permanent:
                self._permanent_failures.add(task_hash)
            else:
                self._failed_tasks.add(task_hash)
                
    def get_stats(self) -> dict:
        with self._lock:
            return {
                "active": len(self._active_tasks),
                "completed": len(self._completed_tasks),
                "failed": len(self._failed_tasks),
                "permanent_failures": len(self._permanent_failures)
            }
