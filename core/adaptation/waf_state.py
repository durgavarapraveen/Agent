from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import Lock
from time import time
from typing import Dict


class WafMode(str, Enum):
    NORMAL = "NORMAL"
    CAUTIOUS = "CAUTIOUS"
    LOW_RATE = "LOW_RATE"
    PASSIVE_ONLY = "PASSIVE_ONLY"


# Per-mode strategy: which tool categories are allowed, and concurrency cap.
STRATEGY: Dict[WafMode, Dict] = {
    WafMode.NORMAL: {
        # passive/osint/cache are the safest tier and must be allowed in every
        # mode (PASSIVE_ONLY is the most restrictive and still permits them).
        "allowed_categories": {"passive", "osint", "cache", "recon", "fingerprint",
                               "crawl", "active", "brute", "exploit"},
        "concurrency": 8,
        "delay_ms": 0,
    },
    WafMode.CAUTIOUS: {
        "allowed_categories": {"passive", "osint", "cache", "recon", "fingerprint",
                               "crawl", "active"},
        "concurrency": 3,
        "delay_ms": 500,
    },
    WafMode.LOW_RATE: {
        "allowed_categories": {"passive", "osint", "cache", "recon", "fingerprint",
                               "targeted"},
        "concurrency": 1,
        "delay_ms": 2000,
    },
    WafMode.PASSIVE_ONLY: {
        "allowed_categories": {"passive", "osint", "cache"},
        "concurrency": 1,
        "delay_ms": 5000,
    },
}


@dataclass
class TargetWafState:
    target: str
    blocks: int = 0
    successes: int = 0
    mode: WafMode = WafMode.NORMAL
    last_block_at: float = 0.0

    def as_dict(self) -> Dict:
        return {
            "target": self.target, "blocks": self.blocks, "successes": self.successes,
            "mode": self.mode.value, "last_block_at": self.last_block_at,
        }


class WafStateMachine:

    def __init__(self, block_thresholds=(1, 3, 5), recovery_successes: int = 10,
                 cooloff_seconds: int = 300):
        self._states: Dict[str, TargetWafState] = {}
        self._lock = Lock()
        self.thresholds = block_thresholds
        self.recovery_successes = recovery_successes
        self.cooloff_seconds = cooloff_seconds

    def _get(self, target: str) -> TargetWafState:
        st = self._states.get(target)
        if st is None:
            st = TargetWafState(target=target)
            self._states[target] = st
        return st

    def record_block(self, target: str) -> WafMode:
        with self._lock:
            st = self._get(target)
            st.blocks += 1
            st.last_block_at = time()
            b2c, b2l, b2p = self.thresholds
            if st.blocks >= b2p:
                st.mode = WafMode.PASSIVE_ONLY
            elif st.blocks >= b2l:
                st.mode = WafMode.LOW_RATE
            elif st.blocks >= b2c:
                st.mode = WafMode.CAUTIOUS
            return st.mode

    def record_success(self, target: str) -> WafMode:
        with self._lock:
            st = self._get(target)
            st.successes += 1
            # Slow, streak-based recovery.
            if st.successes >= self.recovery_successes and time() - st.last_block_at > self.cooloff_seconds:
                st.blocks = max(0, st.blocks - 1)
                st.successes = 0
                if st.blocks == 0:
                    st.mode = WafMode.NORMAL
                elif st.blocks <= self.thresholds[0]:
                    st.mode = WafMode.CAUTIOUS
            return st.mode

    def mode_for(self, target: str) -> WafMode:
        with self._lock:
            return self._get(target).mode

    def strategy(self, target: str) -> Dict:
        return STRATEGY[self.mode_for(target)]

    def is_tool_allowed(self, target: str, category: str) -> bool:
        return (category or "").lower() in self.strategy(target)["allowed_categories"]

    def snapshot(self) -> Dict[str, Dict]:
        with self._lock:
            return {t: s.as_dict() for t, s in self._states.items()}


_SINGLETON: WafStateMachine | None = None


def get_waf_state() -> WafStateMachine:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = WafStateMachine()
    return _SINGLETON
