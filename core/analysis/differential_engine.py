"""Phase 11.1 — Differential request/response engine.

Baseline-versus-variant comparisons across status, headers, body structure,
semantics, DOM, cookies, redirects, timing distributions, and side effects.
Identity-aware and state-aware comparisons with configurable noise thresholds.
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLDS: Dict[str, float] = {
    "status_code_mismatch": 1.0,
    "header_divergence": 0.6,
    "body_structure_divergence": 0.7,
    "body_semantic_divergence": 0.5,
    "dom_divergence": 0.7,
    "cookie_divergence": 0.8,
    "redirect_divergence": 0.9,
    "timing_divergence_ms": 500.0,
    "side_effect_divergence": 0.9,
    "content_length_ratio": 0.2,
}


@dataclass(frozen=True)
class ResponseSnapshot:
    snapshot_id: str = ""
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    headers: Tuple[Tuple[str, str], ...] = ()
    body_hash: str = ""
    body_length: int = 0
    body_structure: str = ""
    dom_hash: str = ""
    dom_element_count: int = 0
    cookies: Tuple[Tuple[str, str], ...] = ()
    redirect_chain: Tuple[str, ...] = ()
    response_time_ms: float = 0.0
    side_effects: Tuple[str, ...] = ()
    identity: str = ""
    state_context: str = ""
    timestamp: float = 0.0

    def header_dict(self) -> Dict[str, str]:
        return {k.lower(): v for k, v in self.headers}


@dataclass
class Anomaly:
    anomaly_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    dimension: str = ""
    severity: str = "info"
    baseline_value: Any = None
    variant_value: Any = None
    confidence: float = 0.0
    explanation: str = ""
    experiment_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id, "dimension": self.dimension,
            "severity": self.severity, "confidence": self.confidence,
            "explanation": self.explanation, "experiment_id": self.experiment_id,
        }


@dataclass
class DiffResult:
    result_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    baseline: Optional[ResponseSnapshot] = None
    variant: Optional[ResponseSnapshot] = None
    anomalies: List[Anomaly] = field(default_factory=list)
    experiment_id: str = ""

    @property
    def diverged(self) -> bool:
        return bool(self.anomalies)

    def max_severity(self) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if not self.anomalies:
            return "none"
        return max((a.severity for a in self.anomalies), key=lambda s: order.get(s, 0))


class DifferentialRequestEngine:
    """Compare baseline vs variant responses across multiple dimensions."""

    def __init__(self, thresholds: Optional[Dict[str, float]] = None):
        self._thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        self._lock = threading.RLock()
        self._results: List[DiffResult] = []
        self._comparators: Dict[str, Callable] = {
            "status_code": self._compare_status,
            "headers": self._compare_headers,
            "body_structure": self._compare_body_structure,
            "body_length": self._compare_body_length,
            "dom": self._compare_dom,
            "cookies": self._compare_cookies,
            "redirects": self._compare_redirects,
            "timing": self._compare_timing,
            "side_effects": self._compare_side_effects,
        }

    def compare(self, baseline: ResponseSnapshot, variant: ResponseSnapshot,
                experiment_id: str = "", dimensions: Optional[Set[str]] = None) -> DiffResult:
        dims = dimensions or set(self._comparators.keys())
        anomalies: List[Anomaly] = []
        for dim in dims:
            comparator = self._comparators.get(dim)
            if comparator:
                result = comparator(baseline, variant)
                if result:
                    result.experiment_id = experiment_id
                    anomalies.append(result)
        diff = DiffResult(baseline=baseline, variant=variant,
                          anomalies=anomalies, experiment_id=experiment_id)
        with self._lock:
            self._results.append(diff)
        return diff

    def compare_multi(self, baseline: ResponseSnapshot,
                      variants: List[ResponseSnapshot],
                      experiment_id: str = "") -> List[DiffResult]:
        return [self.compare(baseline, v, experiment_id=experiment_id) for v in variants]

    def register_comparator(self, name: str, fn: Callable) -> None:
        self._comparators[name] = fn

    def get_results(self, experiment_id: str = "") -> List[DiffResult]:
        with self._lock:
            if experiment_id:
                return [r for r in self._results if r.experiment_id == experiment_id]
            return list(self._results)

    def _compare_status(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        if b.status_code != v.status_code:
            sev = "high" if abs(b.status_code - v.status_code) >= 200 else "medium"
            return Anomaly(dimension="status_code", severity=sev,
                           baseline_value=b.status_code, variant_value=v.status_code,
                           confidence=1.0, explanation=f"Status {b.status_code} → {v.status_code}")
        return None

    def _compare_headers(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        bh, vh = b.header_dict(), v.header_dict()
        security_headers = {"content-security-policy", "x-frame-options", "strict-transport-security",
                            "x-content-type-options", "x-xss-protection", "access-control-allow-origin"}
        missing = security_headers & bh.keys() - vh.keys()
        changed = {k for k in security_headers & bh.keys() & vh.keys() if bh[k] != vh[k]}
        if missing or changed:
            return Anomaly(dimension="headers", severity="medium",
                           baseline_value=list(missing | changed), variant_value=None,
                           confidence=self._thresholds["header_divergence"],
                           explanation=f"Security headers diverged: missing={list(missing)}, changed={list(changed)}")
        return None

    def _compare_body_structure(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        if b.body_structure and v.body_structure and b.body_structure != v.body_structure:
            return Anomaly(dimension="body_structure", severity="medium",
                           baseline_value=b.body_structure, variant_value=v.body_structure,
                           confidence=self._thresholds["body_structure_divergence"],
                           explanation="Response body structure diverged")
        return None

    def _compare_body_length(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        if b.body_length == 0 and v.body_length == 0:
            return None
        max_len = max(b.body_length, v.body_length, 1)
        ratio = abs(b.body_length - v.body_length) / max_len
        if ratio > self._thresholds["content_length_ratio"]:
            return Anomaly(dimension="body_length", severity="low",
                           baseline_value=b.body_length, variant_value=v.body_length,
                           confidence=min(ratio, 1.0),
                           explanation=f"Body length diverged by {ratio:.0%}")
        return None

    def _compare_dom(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        if b.dom_hash and v.dom_hash and b.dom_hash != v.dom_hash:
            return Anomaly(dimension="dom", severity="medium",
                           baseline_value=b.dom_element_count, variant_value=v.dom_element_count,
                           confidence=self._thresholds["dom_divergence"],
                           explanation="DOM structure diverged")
        return None

    def _compare_cookies(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        bc = dict(b.cookies)
        vc = dict(v.cookies)
        new_cookies = set(vc.keys()) - set(bc.keys())
        removed = set(bc.keys()) - set(vc.keys())
        if new_cookies or removed:
            return Anomaly(dimension="cookies", severity="medium" if new_cookies else "low",
                           baseline_value=list(removed), variant_value=list(new_cookies),
                           confidence=self._thresholds["cookie_divergence"],
                           explanation=f"Cookies diverged: new={list(new_cookies)}, removed={list(removed)}")
        return None

    def _compare_redirects(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        if b.redirect_chain != v.redirect_chain:
            return Anomaly(dimension="redirects", severity="high",
                           baseline_value=list(b.redirect_chain), variant_value=list(v.redirect_chain),
                           confidence=self._thresholds["redirect_divergence"],
                           explanation="Redirect chain diverged")
        return None

    def _compare_timing(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        delta = abs(b.response_time_ms - v.response_time_ms)
        if delta > self._thresholds["timing_divergence_ms"]:
            return Anomaly(dimension="timing", severity="medium",
                           baseline_value=b.response_time_ms, variant_value=v.response_time_ms,
                           confidence=min(delta / (self._thresholds["timing_divergence_ms"] * 3), 1.0),
                           explanation=f"Timing diverged by {delta:.0f}ms")
        return None

    def _compare_side_effects(self, b: ResponseSnapshot, v: ResponseSnapshot) -> Optional[Anomaly]:
        if b.side_effects != v.side_effects:
            return Anomaly(dimension="side_effects", severity="high",
                           baseline_value=list(b.side_effects), variant_value=list(v.side_effects),
                           confidence=self._thresholds["side_effect_divergence"],
                           explanation="Side effects diverged between baseline and variant")
        return None
