"""
EscalationGate — async approval queue for high-impact autonomous actions.

The gate decides whether an action may proceed:

  * risk at or below AUTO_APPROVE_MAX_RISK  -> AUTO_APPROVED immediately.
  * higher risk, interactive TTY (attended)  -> classic y/n prompt.
  * higher risk, UNATTENDED_MODE             -> parked as PENDING in a JSON queue;
    an operator resolves it via the resolver CLI, the REST API, or a generic
    webhook callback. If no decision arrives within the timeout, a configurable
    safe default is applied (deny by default).

State lives in data/approvals/queue.json so decisions survive across processes
(the running agent polls the file; the resolver writes to it).

Config (.env):
  UNATTENDED_MODE=false
  AUTO_APPROVE_MAX_RISK=MEDIUM          # LOW|MEDIUM|HIGH|CRITICAL
  ESCALATION_TIMEOUT_SECONDS=1800
  ESCALATION_DEFAULT_ON_TIMEOUT=deny    # deny|approve
  ESCALATION_POLL_SECONDS=5
  ESCALATION_WEBHOOK_URL=               # optional outbound notification
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_QUEUE_DIR = Path("data/approvals")
_QUEUE_FILE = _QUEUE_DIR / "queue.json"


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any, default: "RiskLevel" = None) -> "RiskLevel":
        if isinstance(value, RiskLevel):
            return value
        if isinstance(value, (int, float)):
            try:
                return cls(int(value))
            except ValueError:
                return default or cls.MEDIUM
        name = str(value or "").strip().upper()
        return cls.__members__.get(name, default or cls.MEDIUM)


class ApprovalStatus(str):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    AUTO_APPROVED = "AUTO_APPROVED"


@dataclass
class ApprovalDecision:
    request_id: str
    action: str
    status: str
    approved: bool
    risk: str
    target: str = ""
    reason: str = ""
    decided_by: str = ""
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EscalationGate:
    """File-backed approval queue with a safe unattended default."""

    def __init__(
        self,
        unattended: Optional[bool] = None,
        auto_approve_max_risk: Optional[RiskLevel] = None,
        timeout_seconds: Optional[int] = None,
        default_on_timeout: Optional[str] = None,
        poll_seconds: Optional[int] = None,
        webhook_url: Optional[str] = None,
        queue_file: Path = _QUEUE_FILE,
    ):
        cfg = self._cfg()
        self.unattended = (
            unattended if unattended is not None
            else (cfg.get_bool("UNATTENDED_MODE", False) if cfg else False)
        )
        self.auto_approve_max_risk = auto_approve_max_risk or RiskLevel.parse(
            cfg.get("AUTO_APPROVE_MAX_RISK", "MEDIUM") if cfg else "MEDIUM", RiskLevel.MEDIUM
        )
        self.timeout_seconds = (
            timeout_seconds if timeout_seconds is not None
            else (cfg.get_int("ESCALATION_TIMEOUT_SECONDS", 1800) if cfg else 1800)
        )
        self.default_on_timeout = (
            default_on_timeout
            or (cfg.get("ESCALATION_DEFAULT_ON_TIMEOUT", "deny") if cfg else "deny")
        ).lower()
        self.poll_seconds = max(1, (
            poll_seconds if poll_seconds is not None
            else (cfg.get_int("ESCALATION_POLL_SECONDS", 5) if cfg else 5)
        ))
        self.webhook_url = webhook_url or (cfg.get("ESCALATION_WEBHOOK_URL", "") if cfg else "")
        self.queue_file = Path(queue_file)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ config

    @staticmethod
    def _cfg():
        try:
            from core.common.config import get_config
            return get_config()
        except Exception:
            return None

    # -------------------------------------------------------------- queue I/O

    def _read_queue(self) -> Dict[str, Dict[str, Any]]:
        try:
            if self.queue_file.exists():
                with open(self.queue_file, "r", encoding="utf-8") as f:
                    return json.load(f) or {}
        except Exception as e:
            logger.debug(f"[Escalation] queue read error: {e}")
        return {}

    def _write_queue(self, data: Dict[str, Dict[str, Any]]) -> None:
        try:
            self.queue_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.queue_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(tmp, self.queue_file)
        except Exception as e:
            logger.error(f"[Escalation] queue write error: {e}")

    # ------------------------------------------------------------- public API

    async def request_approval(
        self,
        action: str,
        risk_level: Any = RiskLevel.HIGH,
        details: Optional[Dict[str, Any]] = None,
        target: str = "",
        timeout_seconds: Optional[int] = None,
    ) -> ApprovalDecision:
        """Request approval for an action. Returns a resolved ApprovalDecision."""
        risk = RiskLevel.parse(risk_level, RiskLevel.HIGH)
        details = details or {}
        req_id = uuid.uuid4().hex[:12]

        decision = ApprovalDecision(
            request_id=req_id, action=action, status=ApprovalStatus.PENDING,
            approved=False, risk=risk.name, target=target, details=details,
        )

        # 1. Auto-approve low-risk actions.
        if risk <= self.auto_approve_max_risk:
            decision.status = ApprovalStatus.AUTO_APPROVED
            decision.approved = True
            decision.decided_at = time.time()
            decision.decided_by = "policy:auto"
            decision.reason = f"risk {risk.name} <= AUTO_APPROVE_MAX_RISK {self.auto_approve_max_risk.name}"
            logger.info(f"[Escalation] AUTO-APPROVED '{action}' (risk={risk.name})")
            return decision

        # 2. Attended terminal: keep the interactive prompt.
        if not self.unattended and sys.stdin and sys.stdin.isatty():
            return self._interactive_prompt(decision)

        # 3. Unattended: park in the queue and wait for an out-of-band decision.
        async with self._lock:
            q = self._read_queue()
            q[req_id] = decision.to_dict()
            self._write_queue(q)
        await self._notify_webhook(decision)

        logger.warning(
            f"[Escalation] APPROVAL REQUIRED (unattended) id={req_id} action='{action}' "
            f"risk={risk.name} target='{target}'. Resolve with: "
            f"python -m core.escalation.resolve approve {req_id}"
        )

        deadline = time.time() + (timeout_seconds or self.timeout_seconds)
        while time.time() < deadline:
            await asyncio.sleep(self.poll_seconds)
            rec = self._read_queue().get(req_id)
            if not rec:
                continue
            status = rec.get("status")
            if status in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED):
                decision.status = status
                decision.approved = status == ApprovalStatus.APPROVED
                decision.decided_at = rec.get("decided_at") or time.time()
                decision.decided_by = rec.get("decided_by", "operator")
                decision.reason = rec.get("reason", "")
                logger.info(f"[Escalation] id={req_id} resolved -> {status} by {decision.decided_by}")
                return decision

        # 4. Timeout: apply the safe default.
        approved_default = self.default_on_timeout == "approve"
        decision.status = ApprovalStatus.EXPIRED
        decision.approved = approved_default
        decision.decided_at = time.time()
        decision.decided_by = "policy:timeout"
        decision.reason = f"no decision within {timeout_seconds or self.timeout_seconds}s; default={self.default_on_timeout}"
        async with self._lock:
            q = self._read_queue()
            if req_id in q:
                q[req_id].update({
                    "status": ApprovalStatus.EXPIRED, "approved": approved_default,
                    "decided_at": decision.decided_at, "decided_by": "policy:timeout",
                    "reason": decision.reason,
                })
                self._write_queue(q)
        logger.warning(f"[Escalation] id={req_id} EXPIRED -> default {'APPROVE' if approved_default else 'DENY'}")
        return decision

    def _interactive_prompt(self, decision: ApprovalDecision) -> ApprovalDecision:
        print("\n" + "=" * 60)
        print(f"APPROVAL REQUIRED — {decision.action}")
        print(f"Risk: {decision.risk}   Target: {decision.target}")
        if decision.details:
            print(f"Details: {json.dumps(decision.details, default=str)[:500]}")
        print("=" * 60)
        try:
            resp = input("Approve? [YES/NO]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            resp = "NO"
        decision.approved = resp in ("YES", "Y")
        decision.status = ApprovalStatus.APPROVED if decision.approved else ApprovalStatus.DENIED
        decision.decided_at = time.time()
        decision.decided_by = "operator:tty"
        return decision

    async def _notify_webhook(self, decision: ApprovalDecision) -> None:
        if not self.webhook_url:
            return
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self.webhook_url, json={
                    "type": "approval_request",
                    "request": decision.to_dict(),
                    "resolve_hint": f"python -m core.escalation.resolve approve {decision.request_id}",
                })
        except Exception as e:
            logger.debug(f"[Escalation] webhook notify failed: {e}")

    # ------------------------------------------------------- operator actions

    def list_pending(self) -> List[Dict[str, Any]]:
        return [r for r in self._read_queue().values() if r.get("status") == ApprovalStatus.PENDING]

    def decide(self, request_id: str, approved: bool, decided_by: str = "operator",
               reason: str = "") -> bool:
        q = self._read_queue()
        rec = q.get(request_id)
        if not rec or rec.get("status") != ApprovalStatus.PENDING:
            return False
        rec.update({
            "status": ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED,
            "approved": approved, "decided_at": time.time(),
            "decided_by": decided_by, "reason": reason,
        })
        q[request_id] = rec
        self._write_queue(q)
        return True


_GATE: Optional[EscalationGate] = None


def get_escalation_gate() -> EscalationGate:
    """Process-wide singleton gate."""
    global _GATE
    if _GATE is None:
        _GATE = EscalationGate()
    return _GATE
