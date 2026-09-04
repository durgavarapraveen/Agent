import json
import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(token|auth[_-]?token|bearer)\s*[=:]\s*\S+'),
    re.compile(r"(?i)Bearer\s+\S+"),
    re.compile(r'(?i)(secret|private[_-]?key)\s*[=:]\s*\S+'),
    re.compile(r'(?i)(authorization)\s*[=:]\s*\S+(\s+\S+)?'),
    re.compile(r'(?i)(cookie)\s*[=:]\s*\S+'),
    re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b'),  # base64 blobs
    re.compile(r'\bAKIA[A-Z0-9]{16}\b'),  # AWS keys
    re.compile(r'\bghp_[a-zA-Z0-9]{36}\b'),  # GitHub tokens
]

SECRET_PARAM_KEYS = {"password", "passwd", "pwd", "api_key", "apikey", "token",
                     "secret", "private_key", "authorization", "cookie",
                     "auth_token", "bearer", "credential", "session_id"}

GENESIS_HASH = "0" * 64
AUDIT_SALT = "ANTIGRAVITY_EXEC_AUDIT_2026"


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in SECRET_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
        return value
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in SECRET_PARAM_KEYS else _redact_value(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


class ExecutionAuditor:
    def __init__(self, audit_log_path: str = "data/execution_audit.log"):
        self._path = Path(audit_log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        self._last_hash = self._read_last_hash()

    def log_action(self, action: str, params: Dict[str, Any], result: Any = None) -> Dict[str, Any]:
        safe_params = _redact_value(params)
        safe_result = _redact_value(result) if result is not None else None

        entry_body = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "params": safe_params,
            "result": safe_result,
        }

        current_hash = self._compute_hash(self._last_hash, entry_body)
        full_entry = {
            **entry_body,
            "previous_hash": self._last_hash,
            "current_hash": current_hash,
        }

        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(full_entry) + "\n")

        self._last_hash = current_hash
        return full_entry

    def verify_integrity(self) -> bool:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return True

        expected_prev = GENESIS_HASH
        for line in self._path.read_text(encoding="utf-8").strip().split("\n"):
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("previous_hash") != expected_prev:
                return False
            body = {k: entry[k] for k in ("timestamp", "action", "params", "result") if k in entry}
            computed = self._compute_hash(expected_prev, body)
            if computed != entry.get("current_hash"):
                return False
            expected_prev = entry["current_hash"]
        return True

    def get_entries(self, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._path.exists():
            return []
        entries = []
        for line in self._path.read_text(encoding="utf-8").strip().split("\n"):
            if not line.strip():
                continue
            entry = json.loads(line)
            if action_filter and entry.get("action") != action_filter:
                continue
            entries.append(entry)
        return entries

    def _compute_hash(self, prev_hash: str, body: Dict[str, Any]) -> str:
        raw = f"{prev_hash}{json.dumps(body, sort_keys=True)}{AUDIT_SALT}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _read_last_hash(self) -> str:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH
        lines = self._path.read_text(encoding="utf-8").strip().split("\n")
        for line in reversed(lines):
            if line.strip():
                try:
                    return json.loads(line).get("current_hash", GENESIS_HASH)
                except Exception:
                    pass
        return GENESIS_HASH
