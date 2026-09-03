from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Set


class DuplicateDetector:

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def fingerprint(
        self,
        capability: str,
        target: str,
        endpoint: str,
        identity: str,
        params: Dict[str, Any],
    ) -> str:
        sorted_params = json.dumps(params, sort_keys=True, default=str)
        raw = f"{capability}|{target}|{endpoint}|{identity}|{sorted_params}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, fp: str) -> bool:
        return fp in self._seen

    def record(self, fp: str) -> None:
        self._seen.add(fp)

    def clear(self) -> None:
        self._seen.clear()
