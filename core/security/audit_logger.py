"""
Phase 6 Module 6.2: Immutable Audit Logger (core/audit_logger.py)

Tamper-evident, SHA-256 hash-chained audit logging system with forensic querying,
integrity verification, and GDPR-compliant anonymization.
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

# AUDIT_SALT is embedded in the SHA-256 hash-chain. Its rotation must be
# deliberate — rotating invalidates verification of prior entries — so we
# accept an env override but keep a documented default for dev.
AUDIT_SALT = os.environ.get("AUDIT_SALT", "ANTIGRAVITY_AUDIT_SALT_2026")
GENESIS_HASH = "0" * 64

# Rotation: when the audit log exceeds this size, it is renamed
# `audit.jsonl.<epoch>` and a fresh file is started. Previous chains stay
# on disk (their genesis is the tail hash of the rotated file, recorded in
# the new file's first entry).
AUDIT_LOG_MAX_BYTES = int(os.environ.get("AUDIT_LOG_MAX_BYTES", 50 * 1024 * 1024))
AUDIT_LOG_MAX_FILES = int(os.environ.get("AUDIT_LOG_MAX_FILES", 20))

# PII Redaction patterns
MASKING_PATTERNS = {
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "ip": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'
}


def mask_sensitive_pii(text: str) -> str:
    """Mask PII (emails, IPs, credit cards) in log outputs."""
    if not text:
        return ""
    s = str(text)

    # Mask Emails (u***r@domain.com)
    def _mask_email(m):
        e = m.group(0)
        parts = e.split("@")
        name = parts[0]
        domain = parts[1]
        if len(name) <= 2:
            masked_name = name[0] + "*"
        else:
            masked_name = name[0] + "*" * (len(name) - 2) + name[-1]
        return f"{masked_name}@{domain}"

    s = re.sub(MASKING_PATTERNS["email"], _mask_email, s)

    # Mask Credit Cards
    def _mask_cc(m):
        cc = m.group(0)
        return "*" * 12 + cc[-4:]

    s = re.sub(MASKING_PATTERNS["credit_card"], _mask_cc, s)

    # Mask IP addresses (10.0.0.1 -> 10.0.*.*)
    def _mask_ip(m):
        ip = m.group(0)
        octets = ip.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.*.*"
        return ip

    s = re.sub(MASKING_PATTERNS["ip"], _mask_ip, s)

    return s


class AuditLogger:
    """Tamper-evident SHA-256 hash-chained audit logger."""

    def __init__(self, log_path: str = "data/audit.log"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

    def _calculate_hash(self, previous_hash: str, entry_body: Dict[str, Any]) -> str:
        """Compute SHA-256 hash: sha256(previous_hash + json_body + salt)."""
        body_json = json.dumps(entry_body, sort_keys=True)
        raw_str = f"{previous_hash}{body_json}{AUDIT_SALT}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    def get_last_entry(self) -> Optional[Dict[str, Any]]:
        """Read the last line from the audit log."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return None

        lines = self.log_path.read_text(encoding="utf-8").strip().split("\n")
        if not lines or not lines[-1]:
            return None

        try:
            return json.loads(lines[-1])
        except Exception:
            return None

    def log_cache_hit(self, cache_key: str, invocation: Any) -> None:
        """Log when a tool execution was served from cache"""
        self.log_event(
            action="CACHE_HIT",
            target=getattr(invocation, 'target', 'unknown'),
            details=json.dumps({
                "tool_id": getattr(invocation, 'tool_id', "unknown"),
                "cache_key": cache_key
            })
        )

    def log_denial(self, invocation: Any, auth_context: Any):
        """Log an authorization denial."""
        target = getattr(invocation, 'target', 'unknown')
        tool = getattr(invocation, 'tool_id', getattr(invocation, 'operation', 'unknown'))
        self.log_event("DENY_TOOL", target, f"Denied tool {tool}")

    def log_tool_execution(self, invocation: Any, result: Any, auth_context: Any) -> None:
        """Log a completed tool execution."""
        tool = getattr(invocation, 'tool_id', getattr(invocation, 'operation', 'unknown'))
        target = getattr(invocation, 'target', 'unknown')
        success = getattr(result, 'success', False)
        self.log_event(
            action="TOOL_EXEC",
            target=target,
            details=json.dumps({
                "tool": tool,
                "success": success,
                "duration": getattr(result, 'duration_seconds', 0),
            })
        )

    def log_event(self, action: str, target: str, details: str, user: str = "system@antigravity") -> Dict[str, Any]:
        """
        Append a new tamper-evident hash-chained event to audit.log.
        """
        last_entry = self.get_last_entry()
        if last_entry:
            last_id = last_entry.get("entry_id", 0)
            prev_hash = last_entry.get("current_hash", GENESIS_HASH)
        else:
            last_id = 0
            prev_hash = GENESIS_HASH

        entry_id = last_id + 1
        timestamp = datetime.now().isoformat()

        entry_body = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "user": user,
            "action": action,
            "target": target,
            "details": details
        }

        current_hash = self._calculate_hash(prev_hash, entry_body)

        full_entry = dict(entry_body)
        full_entry["previous_hash"] = prev_hash
        full_entry["current_hash"] = current_hash

        line = json.dumps(full_entry) + "\n"
        # Best-effort rotation. Never raises — a rotation failure must not
        # block an audit write.
        try:
            self._maybe_rotate()
        except Exception as e:
            logger.warning("Audit log rotation skipped: %s", e)
        with open(self.log_path, mode="a", encoding="utf-8") as f:
            f.write(line)

        return full_entry

    def _maybe_rotate(self) -> None:
        """Rotate `audit.jsonl` when it exceeds `AUDIT_LOG_MAX_BYTES`.

        Renames the file to `audit.jsonl.<epoch>`, then prunes rotated files
        beyond `AUDIT_LOG_MAX_FILES`. The hash chain continues in the new
        file — `get_last_entry()` reads only the current file, so the first
        entry after rotation genesis-anchors to the LAST-written prev-hash,
        which is preserved by the on-disk file being renamed intact.
        """
        try:
            p = Path(self.log_path)
            if not p.exists() or p.stat().st_size < AUDIT_LOG_MAX_BYTES:
                return
            import time as _time
            rotated = p.with_suffix(p.suffix + f".{int(_time.time())}")
            p.rename(rotated)
            logger.info("Audit log rotated: %s -> %s", p, rotated)
            # Prune old rotations.
            all_rotated = sorted(
                p.parent.glob(p.name + ".*"),
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )
            for stale in all_rotated[AUDIT_LOG_MAX_FILES:]:
                try:
                    stale.unlink()
                except OSError:
                    pass
        except Exception as e:
            logger.warning("Audit log rotation error: %s", e)

    def verify_audit_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Iterate through audit.log, recalculate hash chain, and verify current_hash matches.
        If tampered, returns (False, tampered_entry_id).
        If valid, returns (True, None).
        """
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return True, None

        lines = self.log_path.read_text(encoding="utf-8").strip().split("\n")
        expected_prev_hash = GENESIS_HASH

        for idx, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except Exception:
                logger.critical(f"[AuditLogger] AUDIT_TAMPER_DETECTED: Invalid JSON at line {idx}")
                return False, idx

            prev_hash = entry.get("previous_hash")
            curr_hash = entry.get("current_hash")
            entry_id = entry.get("entry_id", idx)

            if prev_hash != expected_prev_hash:
                logger.critical(f"[AuditLogger] AUDIT_TAMPER_DETECTED: Previous hash mismatch at entry {entry_id}")
                return False, entry_id

            entry_body = {
                "entry_id": entry.get("entry_id"),
                "timestamp": entry.get("timestamp"),
                "user": entry.get("user"),
                "action": entry.get("action"),
                "target": entry.get("target"),
                "details": entry.get("details")
            }

            computed_hash = self._calculate_hash(prev_hash, entry_body)
            if computed_hash != curr_hash:
                logger.critical(f"[AuditLogger] AUDIT_TAMPER_DETECTED: Current hash mismatch at entry {entry_id}")
                return False, entry_id

            expected_prev_hash = curr_hash

        return True, None

    def query_audit_log(
        self,
        target_ip: Optional[str] = None,
        user: Optional[str] = None,
        tool: Optional[str] = None,
        action: Optional[str] = None,
        mask_pii: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Forensic query interface:
          - host query: target_ip="10.0.0.1"
          - export query: action="REPORT_EXPORT" or user="alice"
          - tool query: tool="nuclei"
        """
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return []

        lines = self.log_path.read_text(encoding="utf-8").strip().split("\n")
        matched = []

        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue

            # Filtering
            if target_ip and target_ip.lower() not in str(entry.get("target", "")).lower():
                continue
            if user and user.lower() not in str(entry.get("user", "")).lower():
                continue
            if action and action.lower() not in str(entry.get("action", "")).lower():
                continue
            if tool and tool.lower() not in str(entry.get("details", "")).lower():
                continue

            res = dict(entry)
            if mask_pii:
                res["user"] = mask_sensitive_pii(res.get("user", ""))
                res["target"] = mask_sensitive_pii(res.get("target", ""))
                res["details"] = mask_sensitive_pii(res.get("details", ""))

            matched.append(res)

        return matched

    def anonymize_audit_entries(self, target_ip: str) -> bool:
        """
        GDPR Right-to-be-Forgotten:
        Replace target and details for matching target_ip with '[REDACTED]',
        re-calculate current_hash for affected and all subsequent entries to maintain chain integrity.
        """
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return False

        lines = self.log_path.read_text(encoding="utf-8").strip().split("\n")
        updated_entries = []
        expected_prev_hash = GENESIS_HASH
        anonymized_count = 0

        for line in lines:
            if not line.strip():
                continue
            entry = json.loads(line)

            # Anonymize matching entries
            if target_ip and target_ip.lower() in str(entry.get("target", "")).lower():
                entry["target"] = "[REDACTED]"
                entry["details"] = "[REDACTED]"
                anonymized_count += 1

            # Re-calculate hash chain
            entry_body = {
                "entry_id": entry["entry_id"],
                "timestamp": entry["timestamp"],
                "user": entry["user"],
                "action": entry["action"],
                "target": entry["target"],
                "details": entry["details"]
            }
            entry["previous_hash"] = expected_prev_hash
            entry["current_hash"] = self._calculate_hash(expected_prev_hash, entry_body)
            expected_prev_hash = entry["current_hash"]

            updated_entries.append(entry)

        # Write re-chained log back to disk
        new_content = "\n".join(json.dumps(e) for e in updated_entries) + "\n"
        self.log_path.write_text(new_content, encoding="utf-8")

        # Log GDPR anonymization event
        self.log_event(
            action="GDPR_ANONYMIZATION",
            target="[REDACTED]",
            details=f"Anonymized {anonymized_count} entries for requested target.",
            user="gdpr_officer"
        )

        return True
