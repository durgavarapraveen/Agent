"""Action fingerprinting + duplicate-action prevention (spec Phase 11).

The tool-gateway freshness gate already suppresses repeated recon keyed by
(target, operation, tool). It does NOT distinguish HTTP method, the parameter
set, the payload class, or the acting identity — so the planner still re-issues
the *same probe* (e.g. "test id on GET /users for SQLi as user A") under a
different random operand and it slips through. The scan logs show this: many
tool calls, few distinct actions, most duplicates.

`ActionFingerprint` is a canonical, operand-independent key over
(tool, method, target-without-operands, param NAMES, payload class, identity).
`ActionLedger` claims a fingerprint before dispatch and records the outcome, so
a conclusively-tried action is never re-run — including across concurrent
agents (claim is atomic). Transient failures are released for one retry.

State is per-session and in-memory (durable checkpointing is a later increment).
Everything is deterministic — no LLM decides dedup.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl

# Param keys whose VALUE is the operand/payload, not part of the action identity.
_VOLATILE_KEYS = {"payload", "value", "data", "body", "operand", "_payload",
                  "_payload_class", "canary", "nonce"}

# Coarse payload-class signatures (deterministic substring probes).
_PAYLOAD_SIGNS = (
    ("sqli", ("' or ", "\" or ", " union ", "sleep(", "' --", "waitfor delay")),
    ("xss", ("<script", "onerror=", "javascript:", "<img", "onload=")),
    ("traversal", ("../", "..\\", "%2e%2e", "/etc/passwd")),
    ("ssti", ("{{", "${", "<%=", "#{")),
    ("cmdi", (";id", "|id", "$(", "&&", "`id`")),
    ("ssrf", ("169.254.169.254", "http://localhost", "file://", "gopher://")),
)


def payload_class(operation: str, params: Dict[str, Any]) -> str:
    """Infer a coarse payload class from the operation + param values."""
    hay = (operation or "").lower()
    for v in (params or {}).values():
        hay += " " + str(v).lower()
    for name, signs in _PAYLOAD_SIGNS:
        if any(s in hay for s in signs):
            return name
    return "generic"


def _norm_target(target: str) -> Tuple[str, Tuple[str, ...]]:
    """Return (canonical target without operands, sorted query param names)."""
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    try:
        u = urlparse(t)
    except ValueError:
        return (target or "").strip().lower(), ()
    host = (u.hostname or "").lower()
    port = f":{u.port}" if u.port else ""
    path = u.path or "/"
    qnames = tuple(sorted({k.lower() for k, _ in parse_qsl(u.query)}))
    return f"{u.scheme}://{host}{port}{path}", qnames


def _identity(params: Dict[str, Any], audit_context: Optional[Dict[str, Any]]) -> str:
    ctx = audit_context or {}
    for k in ("identity", "identity_id", "role", "user", "principal"):
        if ctx.get(k):
            return str(ctx[k]).lower()
    if (params or {}).get("identity"):
        return str(params["identity"]).lower()
    return "anon"


def action_fingerprint(tool_id: str, operation: str, target: str,
                       params: Optional[Dict[str, Any]] = None,
                       audit_context: Optional[Dict[str, Any]] = None) -> str:
    """Canonical, operand-independent fingerprint for an action."""
    params = params or {}
    method = str(params.get("method", "") or operation or "").upper()
    canon_target, qnames = _norm_target(target)
    pnames = sorted({str(k).lower() for k in params.keys()
                     if str(k).lower() not in _VOLATILE_KEYS
                     and not str(k).lower().startswith("method")})
    payload = str(params.get("_payload_class") or payload_class(operation, params))
    key = {
        "tool": (tool_id or "").lower(),
        "op": (operation or "").lower(),
        "method": method,
        "target": canon_target,
        "params": sorted(set(pnames) | set(qnames)),
        "payload_class": payload,
        "identity": _identity(params, audit_context),
    }
    blob = json.dumps(key, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


# Statuses that conclude an action (no value in re-running it).
_CONCLUSIVE = {"success", "failed", "blocked", "skipped_dup"}
# Statuses worth retrying once.
_TRANSIENT = {"timeout", "error", "in_flight"}


class ActionLedger:
    """Per-session record of attempted actions, keyed by fingerprint."""

    def __init__(self):
        self._status: Dict[str, str] = {}
        self._lock = threading.Lock()

    def claim(self, fp: str) -> bool:
        """Atomically claim a fingerprint for execution.

        Returns True if the action may run (never conclusively tried), marking
        it in-flight. Returns False if it was already claimed/concluded — a
        duplicate the caller should skip.
        """
        with self._lock:
            cur = self._status.get(fp)
            if cur is None or cur in ("released",):
                self._status[fp] = "in_flight"
                return True
            return False

    def record(self, fp: str, status: str) -> None:
        s = (status or "").lower()
        with self._lock:
            # A transient outcome releases the claim so one retry is allowed.
            self._status[fp] = "released" if s in _TRANSIENT else (
                s if s in _CONCLUSIVE else "success")

    def status_of(self, fp: str) -> Optional[str]:
        return self._status.get(fp)

    def seen(self, fp: str) -> bool:
        s = self._status.get(fp)
        return s is not None and s != "released"

    def should_execute(self, fp: str) -> Tuple[bool, str]:
        s = self._status.get(fp)
        if s is None or s == "released":
            return True, "new"
        if s == "in_flight":
            return False, "in_flight_duplicate"
        return False, f"already_{s}"

    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for s in self._status.values():
            out[s] = out.get(s, 0) + 1
        out["total"] = len(self._status)
        return out


# ── per-session registry (no ctx dependency; safe from the tool gateway) ────
_LEDGERS: Dict[str, ActionLedger] = {}
_REG_LOCK = threading.Lock()


def get_ledger(session_id: str) -> ActionLedger:
    key = session_id or "default"
    with _REG_LOCK:
        led = _LEDGERS.get(key)
        if led is None:
            led = ActionLedger()
            _LEDGERS[key] = led
        return led


def reset_ledger(session_id: str) -> None:
    with _REG_LOCK:
        _LEDGERS.pop(session_id or "default", None)
