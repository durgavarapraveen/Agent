"""
OPSEC & Detection-Coverage Testing (Phase 4)

Purple-team-aligned replacement for an offensive "detection evasion" module.
This module deliberately does NOT disable logging, delete/alter logs, or
"cover tracks" — anti-forensic log tampering is out of scope. Instead it helps
measure and improve the *blue team's* detection coverage during an authorized
test:

  - Timing jitter to avoid trivial rate-based false positives (benign pacing)
  - Preference for legitimate/expected tooling (reduce noisy signatures)
  - A test matrix that records which actions SHOULD be detected, so the
    engagement can report detection gaps back to defenders.

Nothing here hides activity; it records expectations so gaps can be closed.
"""

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# Actions and the detection sources that SHOULD catch them (for coverage tests).
DETECTION_EXPECTATIONS = {
    "port_scan":      ["IDS/IPS signature", "firewall connection logs"],
    "web_exploit":    ["WAF logs", "application error logs", "access logs"],
    "auth_bruteforce":["auth.log / SIEM auth alerts", "account lockout"],
    "privesc":        ["auditd execve", "sudo logs"],
    "persistence":    ["file integrity monitoring", "new service/cron alerts"],
    "lateral_move":   ["new-host logon correlation", "EDR remote-exec alerts"],
    "cred_access":    ["shadow/secret file access auditing"],
}


@dataclass
class DetectionTest:
    action: str
    expected_sources: List[str]
    detected: Optional[bool] = None      # filled in by the blue team / verifier
    notes: str = ""

    def to_dict(self) -> Dict:
        return {"action": self.action, "expected_sources": self.expected_sources,
                "detected": self.detected, "notes": self.notes}


class OpsecManager:
    """Benign pacing + detection-coverage bookkeeping (no anti-forensics)."""

    def __init__(self, seed: int = 1337):
        # Deterministic LCG so behavior is testable without global RNG state.
        self._state = seed & 0xFFFFFFFF
        self.tests: List[DetectionTest] = []

    def _rand01(self) -> float:
        # Numerical Recipes LCG
        self._state = (1664525 * self._state + 1013904223) & 0xFFFFFFFF
        return self._state / 0xFFFFFFFF

    def jitter(self, base_sec: float = 1.0, spread: float = 0.5) -> float:
        """Return a jittered delay in [base*(1-spread), base*(1+spread)]."""
        factor = 1.0 + (self._rand01() * 2 - 1) * spread
        return round(max(0.0, base_sec * factor), 3)

    def prefer_legit_tool(self, candidates: List[str]) -> str:
        """Pick the most 'expected'/low-noise tool from candidates."""
        # Prefer common admin tools already likely present on targets.
        preference = ["curl", "wget", "dig", "nmap", "python3", "bash"]
        for p in preference:
            if p in candidates:
                return p
        return candidates[0] if candidates else ""

    def register_test(self, action: str, notes: str = "") -> DetectionTest:
        """Record that an action was performed and what should have caught it."""
        t = DetectionTest(action=action,
                          expected_sources=DETECTION_EXPECTATIONS.get(action, ["SIEM"]),
                          notes=notes)
        self.tests.append(t)
        return t

    def mark_detected(self, action: str, detected: bool, notes: str = "") -> bool:
        for t in self.tests:
            if t.action == action and t.detected is None:
                t.detected = detected
                if notes:
                    t.notes = notes
                return True
        return False

    def coverage_report(self) -> Dict:
        total = len(self.tests)
        assessed = [t for t in self.tests if t.detected is not None]
        detected = [t for t in assessed if t.detected]
        gaps = [t.to_dict() for t in assessed if t.detected is False]
        return {
            "actions_performed": total,
            "assessed": len(assessed),
            "detected": len(detected),
            "detection_rate": round(100.0 * len(detected) / len(assessed), 1) if assessed else None,
            "detection_gaps": gaps,
            "tests": [t.to_dict() for t in self.tests],
        }
