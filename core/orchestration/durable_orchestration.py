"""Phase 17.1 — Durable orchestration and exactly-once-ish control.

Resumable scans with durable event logs, idempotent job IDs, retry semantics,
lease handling, dead-letter queues, and deterministic checkpointing. Separates
logical experiment identity from attempt identity.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class JobState(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTERED = "dead_lettered"
    CANCELLED = "cancelled"


class EventType(str, Enum):
    JOB_CREATED = "job_created"
    JOB_LEASED = "job_leased"
    JOB_STARTED = "job_started"
    JOB_COMPLETED = "job_completed"
    JOB_FAILED = "job_failed"
    JOB_RETRIED = "job_retried"
    JOB_DEAD_LETTERED = "job_dead_lettered"
    JOB_CANCELLED = "job_cancelled"
    CHECKPOINT_SAVED = "checkpoint_saved"
    CHECKPOINT_RESTORED = "checkpoint_restored"
    LEASE_RENEWED = "lease_renewed"
    LEASE_EXPIRED = "lease_expired"


@dataclass
class DurableEvent:
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    event_type: EventType = EventType.JOB_CREATED
    job_id: str = ""
    attempt_id: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id, "type": self.event_type.value,
            "job_id": self.job_id, "attempt_id": self.attempt_id,
            "timestamp": self.timestamp, "data": self.data,
        }


@dataclass
class JobDescriptor:
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    experiment_id: str = ""
    task_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: str = ""
    state: JobState = JobState.PENDING
    attempt_count: int = 0
    max_retries: int = 3
    current_attempt_id: str = ""
    lease_holder: str = ""
    lease_expires: float = 0.0
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    last_error: str = ""
    checkpoint: Optional[Dict[str, Any]] = None

    def idempotency(self) -> str:
        if self.idempotency_key:
            return self.idempotency_key
        raw = f"{self.experiment_id}:{self.task_type}:{json.dumps(self.payload, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]


DEFAULT_ORCHESTRATION_CONFIG: Dict[str, Any] = {
    "max_retries": 3,
    "lease_duration_s": 300,
    "dead_letter_after_retries": True,
    "checkpoint_interval_s": 60,
    "max_events_in_memory": 50_000,
    "max_dead_letter_size": 1000,
}


class EventLog:
    """Append-only durable event log for scan operations."""

    def __init__(self, max_events: int = 50_000):
        self._lock = threading.RLock()
        self._events: List[DurableEvent] = []
        self._max = max_events

    def append(self, event: DurableEvent) -> str:
        with self._lock:
            if len(self._events) >= self._max:
                self._events = self._events[-(self._max // 2):]
            self._events.append(event)
        return event.event_id

    def get_events(self, job_id: str = "", event_type: Optional[EventType] = None,
                   limit: int = 100) -> List[DurableEvent]:
        with self._lock:
            filtered = self._events
            if job_id:
                filtered = [e for e in filtered if e.job_id == job_id]
            if event_type:
                filtered = [e for e in filtered if e.event_type == event_type]
            return list(filtered[-limit:])

    def count(self) -> int:
        return len(self._events)


class DeadLetterQueue:
    """Holds jobs that exhausted retries for manual inspection."""

    def __init__(self, max_size: int = 1000):
        self._lock = threading.RLock()
        self._items: List[JobDescriptor] = []
        self._max = max_size

    def enqueue(self, job: JobDescriptor) -> bool:
        with self._lock:
            if len(self._items) >= self._max:
                return False
            self._items.append(job)
        return True

    def peek(self, limit: int = 10) -> List[JobDescriptor]:
        with self._lock:
            return list(self._items[:limit])

    def dequeue(self, job_id: str) -> Optional[JobDescriptor]:
        with self._lock:
            for i, j in enumerate(self._items):
                if j.job_id == job_id:
                    return self._items.pop(i)
        return None

    def size(self) -> int:
        return len(self._items)


class DurableOrchestrator:
    """Resumable scan orchestration with exactly-once-ish semantics."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_ORCHESTRATION_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._jobs: Dict[str, JobDescriptor] = {}
        self._idempotency_index: Dict[str, str] = {}
        self._event_log = EventLog(self._config["max_events_in_memory"])
        self._dlq = DeadLetterQueue(self._config["max_dead_letter_size"])
        self._checkpoints: Dict[str, Dict[str, Any]] = {}

    def submit_job(self, experiment_id: str, task_type: str,
                   payload: Dict[str, Any], idempotency_key: str = "",
                   max_retries: Optional[int] = None) -> Tuple[str, bool]:
        job = JobDescriptor(
            experiment_id=experiment_id, task_type=task_type,
            payload=payload, idempotency_key=idempotency_key,
            max_retries=max_retries or self._config["max_retries"],
        )
        idem = job.idempotency()

        with self._lock:
            existing_id = self._idempotency_index.get(idem)
            if existing_id and existing_id in self._jobs:
                return existing_id, True
            self._jobs[job.job_id] = job
            self._idempotency_index[idem] = job.job_id

        self._emit(EventType.JOB_CREATED, job.job_id, data={"experiment": experiment_id})
        return job.job_id, False

    def lease_job(self, job_id: str, worker_id: str) -> Tuple[bool, str]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False, "job not found"
            if job.state not in (JobState.PENDING, JobState.RETRYING):
                return False, f"job state is {job.state.value}"
            if job.lease_expires > time.time() and job.lease_holder != worker_id:
                return False, "job leased by another worker"

            attempt_id = uuid.uuid4().hex[:12]
            job.state = JobState.LEASED
            job.lease_holder = worker_id
            job.lease_expires = time.time() + self._config["lease_duration_s"]
            job.current_attempt_id = attempt_id
            job.attempt_count += 1

        self._emit(EventType.JOB_LEASED, job_id, attempt_id,
                   data={"worker": worker_id, "attempt": job.attempt_count})
        return True, attempt_id

    def start_job(self, job_id: str, attempt_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.current_attempt_id != attempt_id:
                return False
            if job.state != JobState.LEASED:
                return False
            job.state = JobState.RUNNING

        self._emit(EventType.JOB_STARTED, job_id, attempt_id)
        return True

    def complete_job(self, job_id: str, attempt_id: str,
                     result: Optional[Dict[str, Any]] = None) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.current_attempt_id != attempt_id:
                return False
            if job.state != JobState.RUNNING:
                return False
            job.state = JobState.COMPLETED
            job.completed_at = time.time()

        self._emit(EventType.JOB_COMPLETED, job_id, attempt_id, data=result or {})
        return True

    def fail_job(self, job_id: str, attempt_id: str, error: str = "") -> Tuple[bool, str]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.current_attempt_id != attempt_id:
                return False, "invalid job/attempt"
            job.last_error = error

            if job.attempt_count >= job.max_retries:
                if self._config["dead_letter_after_retries"]:
                    job.state = JobState.DEAD_LETTERED
                    self._dlq.enqueue(job)
                    self._emit(EventType.JOB_DEAD_LETTERED, job_id, attempt_id,
                               data={"error": error})
                    return True, "dead_lettered"
                else:
                    job.state = JobState.FAILED
                    self._emit(EventType.JOB_FAILED, job_id, attempt_id,
                               data={"error": error})
                    return True, "failed"
            else:
                job.state = JobState.RETRYING
                job.lease_holder = ""
                job.lease_expires = 0.0
                self._emit(EventType.JOB_RETRIED, job_id, attempt_id,
                           data={"error": error, "attempt": job.attempt_count})
                return True, "retrying"

    def renew_lease(self, job_id: str, worker_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.lease_holder != worker_id:
                return False
            if job.state not in (JobState.LEASED, JobState.RUNNING):
                return False
            job.lease_expires = time.time() + self._config["lease_duration_s"]
        self._emit(EventType.LEASE_RENEWED, job_id, data={"worker": worker_id})
        return True

    def expire_leases(self) -> List[str]:
        expired: List[str] = []
        now = time.time()
        with self._lock:
            for job in self._jobs.values():
                if job.state in (JobState.LEASED, JobState.RUNNING) and job.lease_expires < now:
                    job.state = JobState.RETRYING
                    job.lease_holder = ""
                    expired.append(job.job_id)
        for jid in expired:
            self._emit(EventType.LEASE_EXPIRED, jid)
        return expired

    def save_checkpoint(self, job_id: str, state: Dict[str, Any]) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            job.checkpoint = state
            self._checkpoints[job_id] = {
                "state": state, "timestamp": time.time(),
                "attempt": job.current_attempt_id,
            }
        self._emit(EventType.CHECKPOINT_SAVED, job_id, data={"keys": list(state.keys())})
        return True

    def restore_checkpoint(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cp = self._checkpoints.get(job_id)
            if cp:
                self._emit(EventType.CHECKPOINT_RESTORED, job_id)
                return cp["state"]
        return None

    def get_job(self, job_id: str) -> Optional[JobDescriptor]:
        return self._jobs.get(job_id)

    def get_pending_jobs(self, limit: int = 50) -> List[JobDescriptor]:
        with self._lock:
            pending = [j for j in self._jobs.values()
                       if j.state in (JobState.PENDING, JobState.RETRYING)]
        pending.sort(key=lambda j: j.created_at)
        return pending[:limit]

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.state in (JobState.COMPLETED, JobState.CANCELLED):
                return False
            job.state = JobState.CANCELLED
        self._emit(EventType.JOB_CANCELLED, job_id)
        return True

    @property
    def event_log(self) -> EventLog:
        return self._event_log

    @property
    def dead_letter_queue(self) -> DeadLetterQueue:
        return self._dlq

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_state: Dict[str, int] = {}
            for j in self._jobs.values():
                by_state[j.state.value] = by_state.get(j.state.value, 0) + 1
        return {
            "total_jobs": len(self._jobs),
            "by_state": by_state,
            "events": self._event_log.count(),
            "dead_letter": self._dlq.size(),
            "checkpoints": len(self._checkpoints),
        }

    def _emit(self, event_type: EventType, job_id: str, attempt_id: str = "",
              data: Optional[Dict[str, Any]] = None) -> None:
        event = DurableEvent(
            event_type=event_type, job_id=job_id,
            attempt_id=attempt_id, data=data or {},
        )
        self._event_log.append(event)
