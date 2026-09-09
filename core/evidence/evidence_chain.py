"""P0.7 — Evidence chain integrity.

Every finding must carry a tamper-evident evidence chain linking:
  observation -> hypothesis -> validation -> evidence -> finding

The chain is:
  1. Immutable once sealed (frozen dataclass entries)
  2. Hash-linked (each entry references the previous hash)
  3. Timestamped with monotonic + wall clock
  4. Source-attributed (tool, phase, agent)

No finding may reach CONFIRMED without a valid chain.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ChainEntryType(str, Enum):
    OBSERVATION = "observation"
    INDICATOR = "indicator"
    HYPOTHESIS = "hypothesis"
    VALIDATION_ATTEMPT = "validation_attempt"
    VALIDATION_RESULT = "validation_result"
    EVIDENCE = "evidence"
    CONFIRMATION = "confirmation"
    REJECTION = "rejection"


@dataclass(frozen=True)
class ChainEntry:
    entry_id: str
    entry_type: ChainEntryType
    source_tool: str
    phase: str
    content_hash: str
    prev_hash: str
    timestamp_utc: str
    timestamp_mono: float
    data: Tuple[Tuple[str, Any], ...]

    @property
    def data_dict(self) -> Dict[str, Any]:
        return dict(self.data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "entry_type": self.entry_type.value,
            "source_tool": self.source_tool,
            "phase": self.phase,
            "content_hash": self.content_hash,
            "prev_hash": self.prev_hash,
            "timestamp_utc": self.timestamp_utc,
            "data": self.data_dict,
        }


def _compute_hash(entry_type: str, source_tool: str, phase: str,
                  prev_hash: str, data: Dict[str, Any]) -> str:
    payload = json.dumps({
        "type": entry_type, "tool": source_tool, "phase": phase,
        "prev": prev_hash, "data": data,
    }, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


_GENESIS_HASH = "0" * 24


class EvidenceChain:
    """Append-only hash-linked evidence chain for a single finding."""

    def __init__(self, finding_id: str):
        self.finding_id = finding_id
        self._entries: List[ChainEntry] = []
        self._sealed = False

    @property
    def length(self) -> int:
        return len(self._entries)

    @property
    def head_hash(self) -> str:
        if not self._entries:
            return _GENESIS_HASH
        return self._entries[-1].content_hash

    @property
    def sealed(self) -> bool:
        return self._sealed

    def append(self, entry_type: ChainEntryType, source_tool: str,
               phase: str, data: Dict[str, Any]) -> ChainEntry:
        if self._sealed:
            raise RuntimeError("chain is sealed")

        prev = self.head_hash
        content_hash = _compute_hash(
            entry_type.value, source_tool, phase, prev, data)

        entry = ChainEntry(
            entry_id=uuid.uuid4().hex[:12],
            entry_type=entry_type,
            source_tool=source_tool,
            phase=phase,
            content_hash=content_hash,
            prev_hash=prev,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            timestamp_mono=time.monotonic(),
            data=tuple(sorted(data.items())),
        )
        self._entries.append(entry)
        return entry

    def seal(self) -> None:
        self._sealed = True

    def verify(self) -> Tuple[bool, str]:
        if not self._entries:
            return False, "empty chain"
        prev = _GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.prev_hash != prev:
                return False, f"broken link at index {i}"
            expected = _compute_hash(
                entry.entry_type.value, entry.source_tool,
                entry.phase, entry.prev_hash, entry.data_dict)
            if entry.content_hash != expected:
                return False, f"hash mismatch at index {i}"
            prev = entry.content_hash
        return True, "valid"

    def has_type(self, entry_type: ChainEntryType) -> bool:
        return any(e.entry_type == entry_type for e in self._entries)

    def is_confirmation_ready(self) -> Tuple[bool, str]:
        if not self.has_type(ChainEntryType.OBSERVATION):
            return False, "missing observation"
        if not self.has_type(ChainEntryType.EVIDENCE):
            return False, "missing evidence"
        if not self.has_type(ChainEntryType.VALIDATION_RESULT):
            return False, "missing validation result"
        valid, reason = self.verify()
        if not valid:
            return False, f"chain integrity: {reason}"
        return True, "ready"

    def entries(self) -> List[ChainEntry]:
        return list(self._entries)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "length": self.length,
            "head_hash": self.head_hash,
            "sealed": self._sealed,
            "entries": [e.to_dict() for e in self._entries],
        }


class EvidenceChainRegistry:
    """Global registry of evidence chains, keyed by finding_id."""

    _instance: Optional["EvidenceChainRegistry"] = None

    @classmethod
    def get(cls) -> "EvidenceChainRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        cls._instance = None

    def __init__(self):
        self._chains: Dict[str, EvidenceChain] = {}

    def get_or_create(self, finding_id: str) -> EvidenceChain:
        if finding_id not in self._chains:
            self._chains[finding_id] = EvidenceChain(finding_id)
        return self._chains[finding_id]

    def get_chain(self, finding_id: str) -> Optional[EvidenceChain]:
        return self._chains.get(finding_id)

    def require_chain_for_confirmation(self, finding_id: str) -> Tuple[bool, str]:
        chain = self._chains.get(finding_id)
        if chain is None:
            return False, "no evidence chain exists"
        return chain.is_confirmation_ready()

    @property
    def size(self) -> int:
        return len(self._chains)
