
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_QUEUE_FILE = Path("data/review_queue/queue.json")

STATUS_SUCCESS = "SUCCESS"
STATUS_NEEDS_MANUAL = "NEEDS_MANUAL"
STATUS_PARTIAL = "PARTIAL"


def _pg():
    try:
        from core.database.pg_store import ReviewRepo
        # cheap reachability check
        ReviewRepo.summary()
        return ReviewRepo
    except Exception as e:
        logger.debug(f"[ReviewQueue] Postgres unavailable, using file fallback: {e}")
        return None


class ReviewQueue:

    def __init__(self, queue_file: Path = _QUEUE_FILE):
        self.queue_file = Path(queue_file)
        self._lock = threading.Lock()

    def _read(self) -> List[Dict[str, Any]]:
        try:
            if self.queue_file.exists():
                return json.loads(self.queue_file.read_text(encoding="utf-8")) or []
        except Exception as e:
            logger.debug(f"[ReviewQueue] read error: {e}")
        return []

    def _write(self, items: List[Dict[str, Any]]) -> None:
        try:
            self.queue_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.queue_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(items, indent=2, default=str), encoding="utf-8")
            tmp.replace(self.queue_file)
        except Exception as e:
            logger.error(f"[ReviewQueue] write error: {e}")

    def record(
        self,
        target: str,
        title: str,
        status: str,
        category: str = "",
        severity: str = "",
        steps: int = 0,
        evidence: str = "",
        tried_summary: str = "",
        manual_guidance: str = "",
        history: Optional[List[Dict[str, Any]]] = None,
        scan_id: str = "",
    ) -> Dict[str, Any]:
        now = time.time()
        rec = {
            "id": uuid.uuid4().hex[:12],
            "timestamp": now,
            "created_at": now,
            "target": target,
            "title": title,
            "status": status,
            "category": category,
            "severity": severity,
            "steps": steps,
            "evidence": str(evidence)[:2000],
            "tried_summary": str(tried_summary)[:2000],
            "manual_guidance": str(manual_guidance)[:2000],
            "history": (history or [])[-15:],
            "scan_id": scan_id,
        }
        repo = _pg()
        if repo is not None:
            try:
                repo.record(rec)
                logger.info(f"[ReviewQueue] recorded {status} (pg): {title} ({target})")
                return rec
            except Exception as e:
                logger.warning(f"[ReviewQueue] pg insert failed, falling back to file: {e}")
        with self._lock:
            items = self._read()
            items.append(rec)
            if len(items) > 1000:
                items = items[-1000:]
            self._write(items)
        logger.info(f"[ReviewQueue] recorded {status} (file): {title} ({target})")
        return rec

    def all(self, limit: int = 200) -> List[Dict[str, Any]]:
        repo = _pg()
        if repo is not None:
            return repo.all(limit)
        return list(reversed(self._read()))[:limit]

    def by_status(self, status: str, limit: int = 200) -> List[Dict[str, Any]]:
        repo = _pg()
        if repo is not None:
            return repo.by_status(status, limit)
        return [r for r in reversed(self._read()) if r.get("status") == status][:limit]

    def successes(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self.by_status(STATUS_SUCCESS, limit)

    def manual_followups(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self.by_status(STATUS_NEEDS_MANUAL, limit)

    def summary(self) -> Dict[str, Any]:
        repo = _pg()
        if repo is not None:
            return repo.summary()
        items = self._read()
        return {
            "total": len(items),
            "success": sum(1 for r in items if r.get("status") == STATUS_SUCCESS),
            "needs_manual": sum(1 for r in items if r.get("status") == STATUS_NEEDS_MANUAL),
            "partial": sum(1 for r in items if r.get("status") == STATUS_PARTIAL),
        }

    def resolve(self, record_id: str, note: str = "") -> bool:
        repo = _pg()
        if repo is not None:
            try:
                return repo.resolve(record_id, note)
            except Exception as e:
                logger.warning(f"[ReviewQueue] pg resolve failed, trying file: {e}")
        with self._lock:
            items = self._read()
            for r in items:
                if r.get("id") == record_id:
                    r["status"] = "RESOLVED"
                    r["resolved_at"] = time.time()
                    r["resolution_note"] = note[:500]
                    self._write(items)
                    return True
        return False


_QUEUE: Optional[ReviewQueue] = None


def get_review_queue() -> ReviewQueue:
    global _QUEUE
    if _QUEUE is None:
        _QUEUE = ReviewQueue()
    return _QUEUE
