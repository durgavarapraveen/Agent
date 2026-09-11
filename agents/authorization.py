
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class ExploitTier(Enum):
    POC = 1          # Read-only proof, no side effects
    SHALLOW = 2      # Low impact, reversible (test accounts, temp files)
    DEEP = 3         # High impact, irreversible (RCE, data exfil)


class AuthorizationManager:

    def __init__(self, scope: Dict = None, audit_dir: str = ".audit_logs"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(exist_ok=True)
        if scope and scope.get("domains"):
            self.scope = scope
        else:
            self.scope = {}
            logger.warning("AuthorizationManager created with no scope — all domain checks will fail")

    def verify_domain(self, domain: str) -> bool:
        from core.security.authorization import TargetScopeValidator
        return TargetScopeValidator.get().is_authorized(domain)

    def verify_tier(self, tier: ExploitTier) -> bool:
        allowed = self.scope.get("max_tier", "POC")
        allowed_num = {"POC": 1, "SHALLOW": 2, "DEEP": 3}.get(allowed, 1)
        return tier.value <= allowed_num

    async def authorize_exploit(
        self,
        domain: str,
        vuln_type: str,
        tier: ExploitTier,
        payload: str,
        require_approval: bool = True
    ) -> bool:

        # 1. Check domain
        if not self.verify_domain(domain):
            self._log_denied(domain, vuln_type, tier, "Domain not in scope")
            return False

        # 2. Check tier
        if not self.verify_tier(tier):
            self._log_denied(domain, vuln_type, tier, "Tier exceeds authorization")
            return False

        # 3. Manual approval for high-impact.
        #
        # Previously this used a blocking sync `input()` inside async paths,
        # which deadlocks non-TTY / server / container deployments. Route
        # DEEP-tier approvals through EscalationGate, which supports webhook
        # + queue-file + optional interactive TTY paths. Environment override:
        # `AUTO_APPROVE_EXPLOITS=1` skips the gate (legacy behavior, dangerous —
        # only intended for CI/dry-run pipelines).
        if require_approval and tier == ExploitTier.DEEP:
            import os
            if os.getenv("AUTO_APPROVE_EXPLOITS", "").strip() != "1":
                approved = self._request_deep_approval(domain, vuln_type, payload)
                if not approved:
                    self._log_denied(domain, vuln_type, tier, "Approval denied or timed out")
                    return False

        # 4. Log approval
        self._log_approved(domain, vuln_type, tier, payload)
        return True

    def _log_approved(self, domain: str, vuln_type: str, tier: ExploitTier, payload: str):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "APPROVED",
            "domain": domain,
            "vuln_type": vuln_type,
            "tier": tier.name,
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "payload_preview": payload[:200],
        }
        self._write_audit_log(entry)
        logger.info(f"✓ Exploit AUTHORIZED: {domain} / {vuln_type} ({tier.name})")

    def _log_denied(self, domain: str, vuln_type: str, tier: ExploitTier, reason: str):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "DENIED",
            "domain": domain,
            "vuln_type": vuln_type,
            "tier": tier.name,
            "reason": reason,
        }
        self._write_audit_log(entry)
        logger.warning(f"✗ Exploit DENIED: {domain} / {reason}")

    def _request_deep_approval(self, domain: str, vuln_type: str, payload: str) -> bool:
        import asyncio as _aio
        try:
            from core.escalation.escalation_gate import get_escalation_gate, RiskLevel
        except Exception as e:
            logger.error("EscalationGate unavailable; refusing DEEP action (%s)", e)
            return False

        gate = get_escalation_gate()
        details = {"domain": domain, "vuln_type": vuln_type, "payload_preview": payload[:200]}

        async def _do_request():
            decision = await gate.request_approval(
                action=f"deep_exploit:{vuln_type}",
                risk_level=RiskLevel.HIGH,
                details=details,
                target=domain,
            )
            return getattr(decision, "status", "denied") == "approved"

        # If a loop is running, schedule concurrently; otherwise run one.
        try:
            _aio.get_running_loop()
        except RuntimeError:
            try:
                return _aio.run(_do_request())
            except Exception as e:
                logger.error("Deep-approval request failed: %s", e)
                return False
        # Loop is running: block via future
        try:
            fut = _aio.run_coroutine_threadsafe(_do_request(), _aio.get_running_loop())
            return bool(fut.result(timeout=getattr(gate, "timeout_seconds", 300)))
        except Exception as e:
            logger.error("Deep-approval request failed inside loop: %s", e)
            return False

    def log_exploit_execution(self, domain: str, vuln_id: str, payload: str, result: Dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status": "EXECUTED",
            "domain": domain,
            "vuln_id": vuln_id,
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "result": result,
            "success": result.get("success", False),
        }
        self._write_audit_log(entry)
        logger.info(f"Exploit executed: {vuln_id} → {result.get('success', False)}")

    def _write_audit_log(self, entry: Dict):
        ts = datetime.now().strftime("%Y%m%d")
        log_file = self.audit_dir / f"exploits_{ts}.jsonl"
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry, default=str) + "\n")

    @staticmethod
    def create_scope(domains: List[str], max_tier: str = "POC") -> Dict:
        return {
            "created": datetime.now().isoformat(),
            "domains": domains,
            "max_tier": max_tier,
        }
