"""
Phase 8 Module 8.3: Failure Recovery Engine (core/recovery_engine.py)

AES-256-GCM encrypted state checkpointing, scan resumption skipping completed tasks,
graceful degradation fallbacks (LLM, DB, tool missing), and audit trail logging.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable

from core.encryption import encrypt, decrypt
from core.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class RecoveryEngine:
    """Manages state checkpointing, scan resumption, and graceful component degradation."""

    def __init__(self, checkpoints_dir: str = "checkpoints", audit_log_path: str = "data/audit.log"):
        self.checkpoints_dir = Path(checkpoints_dir)
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self.memory_finding_buffer: List[Dict[str, Any]] = []
        self._periodic_timer: Optional[threading.Timer] = None

    def save_checkpoint(self, scan_id: str, state: Dict[str, Any]) -> str:
        """
        Serialize scan state (completed modules, partial findings, current target, remaining tasks)
        and save encrypted file checkpoints/scan_{scan_id}.enc.
        """
        file_path = self.checkpoints_dir / f"scan_{scan_id}.enc"
        state_payload = {
            "scan_id": scan_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "completed_modules": state.get("completed_modules", []),
            "partial_findings": state.get("partial_findings", []),
            "current_target": state.get("current_target", ""),
            "remaining_tasks": state.get("remaining_tasks", [])
        }

        json_bytes = json.dumps(state_payload).encode("utf-8")
        encrypted_bytes = encrypt(json_bytes)
        file_path.write_bytes(encrypted_bytes)

        self.audit_logger.log_event(
            action="CHECKPOINT_SAVED",
            target=state.get("current_target", "N/A"),
            details=f"Saved checkpoint for scan_id={scan_id} with {len(state.get('completed_modules', []))} completed modules."
        )
        logger.info(f"[RecoveryEngine] Saved encrypted checkpoint: {file_path}")
        return str(file_path)

    def resume_from_checkpoint(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Decrypt and load state for scan_id if checkpoint exists.
        Returns state dict allowing runner to skip already completed tasks.
        """
        file_path = self.checkpoints_dir / f"scan_{scan_id}.enc"
        if not file_path.exists():
            return None

        try:
            encrypted_bytes = file_path.read_bytes()
            decrypted_bytes = decrypt(encrypted_bytes)
            state = json.loads(decrypted_bytes.decode("utf-8"))

            self.audit_logger.log_event(
                action="SCAN_RESUMED",
                target=state.get("current_target", "N/A"),
                details=f"Resumed scan_id={scan_id} from checkpoint. Skipping completed modules: {state.get('completed_modules')}"
            )
            logger.info(f"[RecoveryEngine] Successfully resumed scan_id={scan_id} from checkpoint.")
            return state
        except Exception as e:
            logger.error(f"[RecoveryEngine] Failed to restore checkpoint for scan_id={scan_id}: {e}")
            return None

    def start_periodic_checkpoint_timer(self, scan_id: str, state_supplier: Callable[[], Dict[str, Any]], interval_sec: float = 300.0) -> threading.Timer:
        """
        Start daemonized background timer saving checkpoint state every N seconds (default 5 minutes).
        """
        def _timer_loop():
            try:
                st = state_supplier()
                self.save_checkpoint(scan_id, st)
            except Exception as e:
                logger.warning(f"[RecoveryEngine] Periodic checkpoint error: {e}")

            # Re-arm timer
            self._periodic_timer = threading.Timer(interval_sec, _timer_loop)
            self._periodic_timer.daemon = True
            self._periodic_timer.start()

        timer = threading.Timer(interval_sec, _timer_loop)
        timer.daemon = True
        timer.start()
        self._periodic_timer = timer
        return timer

    def stop_periodic_checkpoint_timer(self):
        """Stop periodic background checkpoint timer."""
        if self._periodic_timer:
            self._periodic_timer.cancel()
            self._periodic_timer = None

    def fallback_llm_decision(self, prompt_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback decision tree when LLM service is unreachable.
        Returns deterministic rule-based decisions.
        """
        self.audit_logger.log_event(
            action="FALLBACK_ACTIVATED",
            target=str(prompt_context.get("target", "N/A")),
            details="LLM service unreachable. Switched to deterministic rule-based fallback logic."
        )

        vtype = str(prompt_context.get("type", "UNKNOWN")).upper()
        if "SQLI" in vtype or "INJECTION" in vtype:
            action = "run_sqlmap_validation"
        elif "WEB" in vtype or "HTTP" in vtype:
            action = "run_nuclei_web_scan"
        else:
            action = "run_nmap_port_scan"

        return {
            "fallback_used": True,
            "recommended_action": action,
            "confidence": 0.70,
            "reason": "Rule-based fallback due to LLM unavailability."
        }

    def buffer_finding_in_memory(self, finding: Dict[str, Any]):
        """Buffer finding in memory if database connection fails."""
        self.memory_finding_buffer.append(finding)
        self.audit_logger.log_event(
            action="DB_FALLBACK_BUFFERED",
            target=str(finding.get("target", "N/A")),
            details=f"Buffered finding in memory. Buffer count: {len(self.memory_finding_buffer)}"
        )

    def flush_memory_buffer(self, db_save_func: Callable[[Dict[str, Any]], bool]) -> int:
        """Flush in-memory findings back to database when connection is restored."""
        flushed_count = 0
        remaining = []
        for item in self.memory_finding_buffer:
            if db_save_func(item):
                flushed_count += 1
            else:
                remaining.append(item)

        self.memory_finding_buffer = remaining
        logger.info(f"[RecoveryEngine] Flushed {flushed_count} in-memory findings to database.")
        return flushed_count
