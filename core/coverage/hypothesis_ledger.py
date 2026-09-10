from __future__ import annotations

import re
import threading
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlsplit

# Coarse vulnerability-class inference from a hypothesis sentence. Order matters
# (first match wins); generic enough for any target, not app-specific.
_CLASS_PATTERNS = [
    ("SQLI", r"\bsql\b|sqli|union select|boolean-based|error-based"),
    ("NOSQLI", r"nosql|\$ne\b|\$gt\b|operator injection"),
    ("XSS", r"\bxss\b|cross-site script|stored script|reflected script"),
    ("IDOR", r"idor|bola|another user|cross-user|object-level|ownership|horizontal"),
    ("AUTH_BYPASS", r"auth bypass|authentication bypass|without.*password|current password|login bypass|jwt|alg:none|algorithm confusion"),
    ("SSRF", r"ssrf|server-side request|metadata endpoint|169\.254"),
    ("XXE", r"xxe|external entity|xml.*entity"),
    ("SSTI", r"ssti|template injection|\{\{.*\}\}"),
    ("RCE", r"\brce\b|remote code|command injection|os command"),
    ("LFI", r"lfi|path traversal|\.\./|file inclusion"),
    ("OPEN_REDIRECT", r"open redirect|redirect to|location header"),
    ("MASS_ASSIGNMENT", r"mass assignment|mass-assignment|privilege escalation via"),
    ("ACCESS_CONTROL", r"access control|authorization|privilege|forbidden bypass"),
    ("CSRF", r"csrf|cross-site request forgery"),
]

_TERMINAL = {"CONFIRMED", "NEGATIVE"}


def infer_vuln_class(hypothesis: str) -> str:
    h = (hypothesis or "").lower()
    for name, pat in _CLASS_PATTERNS:
        if re.search(pat, h):
            return name
    return "GENERIC"


def _endpoint_key(url: str) -> str:
    try:
        sp = urlsplit(url)
        host = (sp.hostname or "").lower()
        path = sp.path or "/"
        # Collapse numeric / uuid / long-hex id segments so /users/1 and
        # /users/2 are the same hypothesis target.
        segs = []
        for seg in path.split("/"):
            if re.fullmatch(r"\d+", seg) or \
               re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", seg) or \
               re.fullmatch(r"[0-9a-f]{16,}", seg):
                segs.append("{id}")
            else:
                segs.append(seg)
        return f"{host}{'/'.join(segs)}"
    except Exception:
        return url or ""


class HypothesisLedger:
    def __init__(self, max_attempts: int = 3):
        self._lock = threading.RLock()
        self._states: Dict[Tuple[str, str], Dict] = {}
        self.max_attempts = max_attempts

    def key(self, url: str, hypothesis: str) -> Tuple[str, str]:
        return (_endpoint_key(url), infer_vuln_class(hypothesis))

    def should_run(self, url: str, hypothesis: str) -> Tuple[bool, str]:
        k = self.key(url, hypothesis)
        with self._lock:
            st = self._states.get(k)
            if st is None:
                return True, "new"
            if st["state"] in _TERMINAL:
                return False, f"already {st['state']}"
            if st["attempts"] >= self.max_attempts:
                return False, f"attempt budget exhausted ({st['attempts']})"
            return True, "retry"

    def record_hypothesis(self, url: str, hypothesis: str, prerequisites: list[str], expected_observation: str) -> None:
        """observation -> hypothesis -> prerequisites -> experiment (init)"""
        k = self.key(url, hypothesis)
        with self._lock:
            st = self._states.get(k) or {"state": "OPEN", "attempts": 0, "confidence": 0.0}
            st["prerequisites"] = prerequisites
            st["expected_observation"] = expected_observation
            self._states[k] = st

    def record_experiment_outcome(self, url: str, hypothesis: str, outcome: str, confidence_delta: float) -> None:
        """experiment -> observation -> oracle -> confidence update"""
        k = self.key(url, hypothesis)
        with self._lock:
            st = self._states.get(k) or {"state": "OPEN", "attempts": 0, "confidence": 0.0}
            st["attempts"] += 1
            st["confidence"] += confidence_delta
            
            # Bound confidence
            st["confidence"] = max(0.0, min(1.0, st["confidence"]))
            
            if st["state"] not in _TERMINAL:
                if outcome in _TERMINAL:
                    st["state"] = outcome
                elif st["confidence"] >= 0.9:
                    st["state"] = "CONFIRMED"
                elif st["attempts"] >= self.max_attempts and st["confidence"] < 0.3:
                    st["state"] = "NEGATIVE"
                    
            self._states[k] = st

    def record(self, url: str, hypothesis: str, outcome: str) -> None:
        # Legacy compat
        self.record_experiment_outcome(url, hypothesis, outcome, 0.0)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {f"{ep}|{cls}": {
                "state": v["state"], 
                "confidence": v.get("confidence", 0.0),
                "attempts": v.get("attempts", 0)
            } for (ep, cls), v in self._states.items()}


def get_ledger(ctx) -> Optional[HypothesisLedger]:
    if ctx is None:
        return None
    led = getattr(ctx, "hypothesis_ledger", None)
    if led is None:
        led = HypothesisLedger()
        try:
            setattr(ctx, "hypothesis_ledger", led)
        except Exception:
            return None
    return led
