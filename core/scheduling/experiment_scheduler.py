from __future__ import annotations

import heapq
from typing import List, Optional, Set

from core.domain.experiment import SecurityExperiment
from core.scheduling.duplicate_detector import DuplicateDetector


class ExperimentScheduler(object):

    def __init__(self, max_queue_size: int = 1000) -> None:
        self.max_queue_size = max_queue_size
        self._heap: List[tuple] = []
        self._counter = 0
        self._detector = DuplicateDetector()
        self._active_ids: Set[str] = set()

    def queue(self, experiment: SecurityExperiment) -> bool:
        if len(self._heap) >= self.max_queue_size:
            return False

        fp = self._detector.fingerprint(
            experiment.capability,
            experiment.endpoint_id,
            experiment.endpoint_id,
            experiment.identity_id,
            experiment.input_parameters,
        )
        if self._detector.is_duplicate(fp):
            return False
        self._detector.record(fp)

        self._counter += 1
        heapq.heappush(self._heap, (-experiment.priority, self._counter, experiment))
        self._active_ids.add(experiment.experiment_id)
        return True

    def next(self) -> Optional[SecurityExperiment]:
        while self._heap:
            _, _, experiment = heapq.heappop(self._heap)
            self._active_ids.discard(experiment.experiment_id)
            return experiment
        return None

    def size(self) -> int:
        return len(self._heap)

    def clear(self) -> None:
        self._heap.clear()
        self._active_ids.clear()
        self._detector.clear()
        self._counter = 0
