"""HypothesisLedger — terminal-state tracking for probe hypotheses (P1-5).

The LLM re-prompt loop tends to re-test the same (endpoint, vulnerability-class)
pair many times (JWT, login, basket IDOR, change-password …), wasting tool
calls and tokens. This ledger gives each hypothesis a small state machine:

    OPEN -> TESTING -> CONFIRMED | NEGATIVE | INCONCLUSIVE

Once a pair reaches a terminal state (CONFIRMED / NEGATIVE) or exhausts its
attempt budget, `should_run` returns False and the probe layer short-circuits
instead of re-executing. State is per-scan, held on the SharedContext.
"""
from __future__ import annotations

import re
import threading
from typing import Dict, Optional, Tuple
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
        """Return (allowed, reason). False when the pair is terminal or the
        attempt budget is exhausted."""
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

    def record(self, url: str, hypothesis: str, outcome: str) -> None:
        """outcome: CONFIRMED | NEGATIVE | INCONCLUSIVE | TESTING."""
        k = self.key(url, hypothesis)
        with self._lock:
            st = self._states.get(k) or {"state": "OPEN", "attempts": 0}
            st["attempts"] += 1
            # Don't let a later INCONCLUSIVE override a terminal verdict.
            if st["state"] not in _TERMINAL:
                st["state"] = outcome
            self._states[k] = st

    def snapshot(self) -> Dict[str, str]:
        with self._lock:
            return {f"{ep}|{cls}": v["state"] for (ep, cls), v in self._states.items()}


def get_ledger(ctx) -> Optional[HypothesisLedger]:
    """Fetch (or lazily create) the ledger on a SharedContext."""
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
