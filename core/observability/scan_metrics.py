from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Optional


@dataclass
class ScanMetrics:
    llm_calls: int = 0
    llm_latency_ms: float = 0.0
    tool_calls: int = 0
    tool_calls_unique: int = 0
    duplicate_tool_calls: int = 0
    duplicate_findings: int = 0
    failed_tools: int = 0
    partial_tools: int = 0
    waf_blocks: int = 0
    requests_sent: int = 0
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    hypotheses_generated: int = 0
    hypotheses_validated: int = 0
    confirmed_findings: int = 0

    def as_dict(self) -> Dict[str, float]:
        d = self.__dict__.copy()
        d.update(self.derived())
        return d

    def derived(self) -> Dict[str, float]:
        u = self.tool_calls or 1
        return {
            "unique_tool_call_ratio": self.tool_calls_unique / u,
            "duplicate_finding_ratio": self.duplicate_findings / max(1, self.confirmed_findings + self.duplicate_findings),
            "validated_finding_ratio": self.hypotheses_validated / max(1, self.hypotheses_generated),
            "useful_action_ratio": (self.tool_calls - self.failed_tools) / u,
            "llm_calls_per_confirmed_finding": self.llm_calls / max(1, self.confirmed_findings),
        }


class MetricsCollector:
    def __init__(self):
        self.metrics = ScanMetrics()
        self._lock = Lock()

    def inc(self, field_name: str, by: float = 1) -> None:
        with self._lock:
            cur = getattr(self.metrics, field_name, 0)
            setattr(self.metrics, field_name, cur + by)

    def snapshot(self) -> Dict[str, float]:
        with self._lock:
            return self.metrics.as_dict()


_SINGLETON: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = MetricsCollector()
    return _SINGLETON
