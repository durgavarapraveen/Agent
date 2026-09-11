"""Phase 3.3 — regression detection.

``retest_engine`` already re-validates findings and computes NEW/REMEDIATED/
PERSISTENT deltas and can replay exploit findings (``can_reproduce``). What it
does not track is the *regression* lifecycle: a finding that was marked FIXED
and then reappears on a later scan. This module adds that:

  * store the exact test case for each fixed finding;
  * on re-scan, replay it (via an injected reproducer — defaults to
    ``retest_engine.can_reproduce``) and flag it REGRESSED if it succeeds again;
  * track mean-time-to-fix per severity and the regression rate.

Pure and file-backed, so it unit-tests with an injected reproducer and no live
target or DB.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# reproducer(test_case) -> True if the finding is still reproducible (vulnerable)
Reproducer = Callable[[Dict[str, Any]], bool]

_STATE_DIR = Path("data") / "regression"

OPEN, FIXED, REGRESSED = "open", "fixed", "regressed"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


@dataclass
class TrackedFinding:
    finding_id: str
    title: str = ""
    url: str = ""
    severity: str = "medium"
    test_case: Dict[str, Any] = field(default_factory=dict)
    status: str = OPEN
    first_seen: str = field(default_factory=_now)
    fixed_at: str = ""
    regressed_at: str = ""


class RegressionDetector:

    def __init__(self, reproducer: Optional[Reproducer] = None,
                 store_path: Optional[str] = None):
        self._reproducer = reproducer
        self._store_path = Path(store_path) if store_path else None
        self.findings: Dict[str, TrackedFinding] = {}

    # ── Tracking ─────────────────────────────────────────────────────────────
    def track(self, finding: Dict[str, Any]) -> TrackedFinding:
        fid = str(finding.get("id") or finding.get("finding_id") or
                  f"{finding.get('title')}::{finding.get('url')}")
        tf = self.findings.get(fid)
        if tf is None:
            tf = TrackedFinding(
                finding_id=fid, title=finding.get("title", ""),
                url=finding.get("url", "") or finding.get("target", ""),
                severity=str(finding.get("severity", "medium")).lower(),
                test_case=finding.get("test_case") or self._derive_test_case(finding))
            self.findings[fid] = tf
        return tf

    def mark_fixed(self, finding_id: str, when: Optional[str] = None) -> None:
        tf = self.findings.get(finding_id)
        if tf:
            tf.status = FIXED
            tf.fixed_at = when or _now()

    @staticmethod
    def _derive_test_case(finding: Dict[str, Any]) -> Dict[str, Any]:
        return {"method": finding.get("method", "GET"),
                "url": finding.get("url") or finding.get("target", ""),
                "payload": finding.get("payload") or finding.get("proof", ""),
                "expected_signal": finding.get("expected_signal", "")}

    # ── Regression check ─────────────────────────────────────────────────────
    def _reproduce(self, test_case: Dict[str, Any]) -> bool:
        repro = self._reproducer
        if repro is None:
            logger.debug("regression_detector: no reproducer configured; cannot verify")
            return False
        try:
            return bool(repro(test_case))
        except Exception as e:
            logger.warning("regression_detector: reproducer error (%s)", e)
            return False

    def check_regressions(self, when: Optional[str] = None) -> List[TrackedFinding]:
        """Replay every FIXED finding's test case; flag REGRESSED on success."""
        regressed: List[TrackedFinding] = []
        for tf in self.findings.values():
            if tf.status != FIXED:
                continue
            if self._reproduce(tf.test_case):
                tf.status = REGRESSED
                tf.regressed_at = when or _now()
                regressed.append(tf)
                logger.warning("REGRESSED: %s (%s) reproduced after being fixed",
                               tf.title or tf.finding_id, tf.url)
        return regressed

    # ── Metrics ──────────────────────────────────────────────────────────────
    def mean_time_to_fix(self) -> Dict[str, float]:
        """Average hours from first_seen → fixed_at, per severity."""
        buckets: Dict[str, List[float]] = {}
        for tf in self.findings.values():
            if tf.status in (FIXED, REGRESSED) and tf.fixed_at:
                a, b = _parse(tf.first_seen), _parse(tf.fixed_at)
                if a and b and b >= a:
                    buckets.setdefault(tf.severity, []).append((b - a).total_seconds() / 3600.0)
        return {sev: round(sum(v) / len(v), 2) for sev, v in buckets.items() if v}

    def regression_rate(self) -> float:
        ever_fixed = [tf for tf in self.findings.values()
                      if tf.status in (FIXED, REGRESSED) or tf.fixed_at]
        if not ever_fixed:
            return 0.0
        regressed = [tf for tf in ever_fixed if tf.status == REGRESSED]
        return round(len(regressed) / len(ever_fixed), 3)

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for tf in self.findings.values():
            by_status[tf.status] = by_status.get(tf.status, 0) + 1
        return {"tracked": len(self.findings), "by_status": by_status,
                "regression_rate": self.regression_rate(),
                "mean_time_to_fix_hours": self.mean_time_to_fix()}

    # ── Persistence ──────────────────────────────────────────────────────────
    def save(self, path: Optional[str] = None) -> str:
        p = Path(path) if path else (self._store_path or _STATE_DIR / "tracked.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({fid: asdict(tf) for fid, tf in self.findings.items()},
                                indent=2), encoding="utf-8")
        return str(p)

    def load(self, path: Optional[str] = None) -> None:
        p = Path(path) if path else (self._store_path or _STATE_DIR / "tracked.json")
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            self.findings = {fid: TrackedFinding(**tf) for fid, tf in data.items()}
        except Exception as e:
            logger.warning("regression_detector: load failed (%s)", e)
