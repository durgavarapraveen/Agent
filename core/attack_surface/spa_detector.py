"""
SPA Catch-All Detection (Phase 8).

Before trusting directory/path fuzzing results, detect if the target
serves an SPA catch-all (e.g., Angular/React router returning the same
shell for all paths).

Algorithm:
1. Request a random nonexistent path
2. Record: status, content_length, title, response_hash
3. Compare fuzz results against baseline
4. If responses match → SPA_CATCH_ALL, not real endpoints
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SPADetector:

    def __init__(self):
        self._baselines: Dict[str, Dict[str, Any]] = {}

    def create_baseline_path(self) -> str:
        """Generate a random path guaranteed not to exist."""
        return f"/__spa_detect_{uuid.uuid4().hex[:12]}"

    def record_baseline(self, host: str, status: int,
                        content_length: int, body: str,
                        title: str = "") -> Dict[str, Any]:
        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
        baseline = {
            "status": status,
            "content_length": content_length,
            "body_hash": body_hash,
            "title": title,
        }
        self._baselines[host] = baseline
        logger.info(f"SPA_BASELINE host={host} status={status} "
                    f"length={content_length} hash={body_hash}")
        return baseline

    def is_catch_all(self, host: str, status: int,
                     content_length: int, body: str) -> bool:
        baseline = self._baselines.get(host)
        if not baseline:
            return False

        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]

        if baseline["status"] != status:
            return False

        length_delta = abs(baseline["content_length"] - content_length)
        if length_delta > 100:
            return False

        if baseline["body_hash"] == body_hash:
            return True

        if length_delta < 50 and baseline["status"] == 200:
            return True

        return False

    def get_baseline(self, host: str) -> Optional[Dict[str, Any]]:
        return self._baselines.get(host)
