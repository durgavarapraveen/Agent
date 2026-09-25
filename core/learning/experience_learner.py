import logging
from collections import defaultdict
from typing import List, Dict, Any, Optional, Protocol

logger = logging.getLogger(__name__)

FAILURE_PATTERN_THRESHOLD = 2


class StorageBackend(Protocol):
    def save(self, key: str, records: List[Dict[str, Any]]) -> None: ...
    def load(self, key: str) -> List[Dict[str, Any]]: ...


class InMemoryStorage:
    def __init__(self):
        self._data: Dict[str, List[Dict[str, Any]]] = {}

    def save(self, key: str, records: List[Dict[str, Any]]) -> None:
        self._data[key] = records

    def load(self, key: str) -> List[Dict[str, Any]]:
        return self._data.get(key, [])


class JSONFileStorage:
    """P1-I5: default PERSISTENT backend so cross-run learning survives process
    restarts (the old InMemoryStorage default silently lost every lesson on
    exit). Stores under the hidden runtime dir; degrades to in-memory semantics
    if the path isn't writable. Generic — no target-specific state."""

    def __init__(self, path: Optional[str] = None):
        import os
        from pathlib import Path
        base = path or os.getenv("EXPERIENCE_STORE_PATH") or str(
            Path(".antigravity") / "experience.json")
        self._path = Path(base)
        self._data: Dict[str, List[Dict[str, Any]]] = {}
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.exists():
                import json
                self._data = json.loads(self._path.read_text(encoding="utf-8")) or {}
        except Exception as e:
            logger.debug("JSONFileStorage load skipped: %s", e)

    def save(self, key: str, records: List[Dict[str, Any]]) -> None:
        self._data[key] = records
        try:
            import json
            self._path.write_text(json.dumps(self._data, default=str), encoding="utf-8")
        except Exception as e:
            logger.debug("JSONFileStorage save skipped: %s", e)

    def load(self, key: str) -> List[Dict[str, Any]]:
        return self._data.get(key, [])


class ExperienceLearner:
    def __init__(self, storage_backend: Optional[Any] = None):
        # P1-I5: persistent by default (was InMemoryStorage → lost on restart).
        if storage_backend is None:
            try:
                storage_backend = JSONFileStorage()
            except Exception:
                storage_backend = InMemoryStorage()
        self.storage = storage_backend
        self._failures: List[Dict[str, Any]] = []
        self._successes: List[Dict[str, Any]] = []
        self._load()

    def record_success(self, strategy: str, test_type: str, outcome: str) -> None:
        record = {"strategy": strategy, "test_type": test_type, "outcome": outcome}
        self._successes.append(record)
        self._persist()
        logger.info(f"EXPERIENCE success strategy={strategy} test_type={test_type}")

    def record_failure(self, strategy: str, test_type: str, reason: str) -> None:
        record = {"strategy": strategy, "test_type": test_type, "reason": reason}
        self._failures.append(record)
        self._persist()
        logger.info(f"EXPERIENCE failure strategy={strategy} test_type={test_type} reason={reason}")

    def detect_patterns(self) -> List[str]:
        failure_counts: Dict[tuple, List[str]] = defaultdict(list)
        for f in self._failures:
            key = (f["strategy"], f["test_type"])
            failure_counts[key].append(f.get("reason", "unknown"))

        patterns = []
        for (strategy, test_type), reasons in failure_counts.items():
            if len(reasons) >= FAILURE_PATTERN_THRESHOLD:
                top_reason = max(set(reasons), key=reasons.count)
                patterns.append(f"{strategy} fails for {test_type}: {top_reason}")
        return patterns

    def get_failure_count(self, strategy: str, test_type: str) -> int:
        return sum(
            1 for f in self._failures
            if f["strategy"] == strategy and f["test_type"] == test_type
        )

    def get_success_rate(self, strategy: str, test_type: str) -> float:
        successes = sum(
            1 for s in self._successes
            if s["strategy"] == strategy and s["test_type"] == test_type
        )
        failures = self.get_failure_count(strategy, test_type)
        total = successes + failures
        if total == 0:
            return 0.0
        return successes / total

    def get_preferred_strategy(self, test_type: str, candidates: List[str], min_rate: float = 0.5) -> Optional[str]:
        best_strategy = None
        best_rate = -1.0
        for strategy in candidates:
            rate = self.get_success_rate(strategy, test_type)
            if rate >= min_rate and rate > best_rate:
                best_rate = rate
                best_strategy = strategy
        return best_strategy

    def _persist(self):
        self.storage.save("failures", self._failures)
        self.storage.save("successes", self._successes)

    def _load(self):
        self._failures = self.storage.load("failures")
        self._successes = self.storage.load("successes")
