from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Operations whose active use is higher-risk; flagged (not blocked) so the
# decision + audit trail record them. Target-agnostic.
_HIGH_RISK_OPS = {
    "sql_injection", "command_injection", "rce", "exploitation",
    "brute_force", "authentication_testing", "deserialization",
}


@dataclass
class GateDecision:
    allowed: bool
    stage: str                 # stage that produced the verdict
    reason: str
    flags: Dict[str, Any] = field(default_factory=dict)


def _target_of(invocation) -> str:
    t = getattr(invocation, "target", None)
    if t:
        return str(t)
    params = getattr(invocation, "params", None) or {}
    return str(params.get("target") or params.get("url") or params.get("domain") or "")


def _host_of(target: str) -> str:
    if not target:
        return ""
    if "://" not in target:
        target = "https://" + target
    try:
        return (urlsplit(target).hostname or "").lower()
    except Exception:
        return ""


class ActionGate:
    @staticmethod
    def evaluate(invocation, ctx=None, tier: str = "POC") -> GateDecision:
        op = (getattr(invocation, "operation", "") or "").lower()
        tool_id = getattr(invocation, "tool_id", "") or ""
        target = _target_of(invocation)

        # 1) SCHEMA — must name a tool/operation and a target.
        if not (tool_id or op):
            return GateDecision(False, "schema", "no tool_id or operation")
        if not target:
            return GateDecision(False, "schema", "no target/url/domain in invocation")

        # 2) SCOPE — target host must be authorised. This is the stage that
        #    rejects out-of-scope LLM plans (e.g. docs.ethers.io) before any tool
        #    touches them.
        host = _host_of(target)
        if host:
            try:
                from core.security.authorization import TargetScopeValidator
                if not TargetScopeValidator.get().is_authorized(host):
                    return GateDecision(False, "scope", f"host {host} out of scope")
            except Exception as e:
                return GateDecision(False, "scope", f"scope check failed (fail-closed): {e}")

        # 3) PRECONDITION — light sanity: http-family ops need an http(s) target.
        http_ops = {"http_analysis", "xss_scanning", "sql_injection",
                    "endpoint_discovery", "web_crawling", "vulnerability_scanning"}
        if op in http_ops and target and "://" in target \
                and not target.lower().startswith(("http://", "https://")):
            return GateDecision(False, "precondition",
                                f"{op} requires http(s) target, got {target[:40]}")

        flags: Dict[str, Any] = {}

        # 4) DUPLICATE — advisory. Records that this (op, host) already ran this
        #    scan; the result cache / freshness gate do the actual short-circuit.
        try:
            if ctx is not None:
                seen = getattr(ctx, "_gate_seen_ops", None)
                if seen is None:
                    seen = set()
                    setattr(ctx, "_gate_seen_ops", seen)
                sig = f"{op}|{host}"
                flags["duplicate"] = sig in seen
                seen.add(sig)
        except Exception as e:
            raise SystemError(f"Policy enforcement failed: {e}") from e

        # 5) RISK — advisory flag for high-risk active operations.
        if op in _HIGH_RISK_OPS:
            flags["high_risk"] = True
            flags["tier"] = tier

        return GateDecision(True, "allow", "passed all stages", flags)
