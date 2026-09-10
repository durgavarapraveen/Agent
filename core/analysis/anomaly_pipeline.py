"""Phase 11.2 — Statistical anomaly pipeline.

Robust timing and behavior analysis using repeated baselines, confidence
intervals, outlier detection, and environmental-noise controls. Separates
transient anomalies from repeatable security-relevant signals.
"""
from __future__ import annotations

import logging
import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "min_baseline_samples": 5,
    "confidence_level": 0.95,
    "outlier_z_threshold": 2.5,
    "max_env_drift_ratio": 0.3,
    "repeat_count_for_confirmation": 3,
    "timing_bucket_ms": 50,
}


@dataclass
class TimingSample:
    response_time_ms: float
    timestamp: float = field(default_factory=time.time)
    identity: str = ""
    endpoint: str = ""
    payload_hash: str = ""
    environment_tag: str = ""


@dataclass
class AnomalySignal:
    signal_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    endpoint: str = ""
    dimension: str = ""
    mean_baseline: float = 0.0
    stddev_baseline: float = 0.0
    observed_value: float = 0.0
    z_score: float = 0.0
    confidence: float = 0.0
    severity: str = "info"
    is_repeatable: bool = False
    repeat_count: int = 0
    environment_drift: bool = False
    explanation: str = ""
    experiment_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id, "endpoint": self.endpoint,
            "dimension": self.dimension, "z_score": self.z_score,
            "confidence": self.confidence, "severity": self.severity,
            "is_repeatable": self.is_repeatable, "repeat_count": self.repeat_count,
            "environment_drift": self.environment_drift,
            "explanation": self.explanation,
        }


class StatisticalAnomalyPipeline:
    """Detect statistically significant anomalies with environmental-noise controls."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._baselines: Dict[str, List[TimingSample]] = {}
        self._signals: List[AnomalySignal] = []
        self._env_baselines: Dict[str, List[float]] = {}

    def record_baseline(self, endpoint: str, sample: TimingSample) -> None:
        with self._lock:
            self._baselines.setdefault(endpoint, []).append(sample)

    def record_environment_probe(self, tag: str, response_time_ms: float) -> None:
        with self._lock:
            self._env_baselines.setdefault(tag, []).append(response_time_ms)

    def detect_environment_drift(self, tag: str, current_ms: float) -> bool:
        with self._lock:
            samples = self._env_baselines.get(tag, [])
        if len(samples) < self._config["min_baseline_samples"]:
            return False
        mean = sum(samples) / len(samples)
        if mean == 0:
            return False
        drift_ratio = abs(current_ms - mean) / mean
        return drift_ratio > self._config["max_env_drift_ratio"]

    def analyze_timing(self, endpoint: str, observed_ms: float,
                       experiment_id: str = "", env_tag: str = "") -> Optional[AnomalySignal]:
        with self._lock:
            samples = self._baselines.get(endpoint, [])
        if len(samples) < self._config["min_baseline_samples"]:
            return None
        values = [s.response_time_ms for s in samples]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        stddev = math.sqrt(variance) if variance > 0 else 0.001
        z_score = (observed_ms - mean) / stddev
        if abs(z_score) < self._config["outlier_z_threshold"]:
            return None
        env_drift = self.detect_environment_drift(env_tag, observed_ms) if env_tag else False
        confidence = min(abs(z_score) / (self._config["outlier_z_threshold"] * 2), 1.0)
        if env_drift:
            confidence *= 0.5
        severity = "high" if abs(z_score) > 4 else "medium" if abs(z_score) > 3 else "low"
        signal = AnomalySignal(
            endpoint=endpoint, dimension="timing", mean_baseline=mean,
            stddev_baseline=stddev, observed_value=observed_ms,
            z_score=z_score, confidence=confidence, severity=severity,
            environment_drift=env_drift, experiment_id=experiment_id,
            explanation=f"Timing {observed_ms:.0f}ms vs baseline {mean:.0f}±{stddev:.0f}ms (z={z_score:.2f})",
        )
        with self._lock:
            self._signals.append(signal)
        return signal

    def confirm_repeatability(self, endpoint: str,
                              probe_fn: Callable[[], float],
                              experiment_id: str = "") -> Optional[AnomalySignal]:
        repeat_count = self._config["repeat_count_for_confirmation"]
        observations = []
        for _ in range(repeat_count):
            observations.append(probe_fn())
        signals = []
        for obs in observations:
            sig = self.analyze_timing(endpoint, obs, experiment_id)
            if sig:
                signals.append(sig)
        if len(signals) >= repeat_count - 1:
            best = max(signals, key=lambda s: abs(s.z_score))
            best.is_repeatable = True
            best.repeat_count = len(signals)
            return best
        return None

    def get_signals(self, endpoint: str = "", repeatable_only: bool = False) -> List[AnomalySignal]:
        with self._lock:
            out = list(self._signals)
        if endpoint:
            out = [s for s in out if s.endpoint == endpoint]
        if repeatable_only:
            out = [s for s in out if s.is_repeatable]
        return out

    def baseline_stats(self, endpoint: str) -> Optional[Dict[str, float]]:
        with self._lock:
            samples = self._baselines.get(endpoint, [])
        if not samples:
            return None
        values = [s.response_time_ms for s in samples]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return {"mean": mean, "stddev": math.sqrt(variance), "count": len(values),
                "min": min(values), "max": max(values)}
