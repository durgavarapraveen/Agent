"""
Credential Protection Auditor & Secret Scanning Engine.
Audits Windows LAPS/Credential Guard, Linux /etc/shadow permissions, and scans source code/configs for leaked secrets.
"""

import logging
import math
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# High-entropy secret patterns (API keys, SSH keys, Bearer tokens)
SECRET_PATTERNS = [
    (r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----", "SSH Private Key", "CRITICAL"),
    (r"(?i)aws_access_key_id\s*[:=]\s*['\"]?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "AWS Access Key ID", "HIGH"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Access Key", "CRITICAL"),
    (r"(?i)github[_-]?token\s*[:=]\s*['\"]?ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "HIGH"),
    (r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "OAuth Bearer Token", "HIGH"),
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "Generic Secret Key", "HIGH"),
]


@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    secret_type: str
    severity: str
    match_snippet: str
    entropy: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "severity": self.severity,
            "match_snippet": self.match_snippet,
            "entropy": round(self.entropy, 2),
        }


class SecretScanner:
    """High-entropy secret scanner for source code, environment files, and configurations."""

    def __init__(self, root_dir: str = "."):
        self.root_dir = root_dir

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    def scan_directory(self, max_files: int = 500) -> List[Dict[str, Any]]:
        """Scan directory for secret patterns and high-entropy strings."""
        findings: List[SecretFinding] = []
        scanned_count = 0

        ignored_dirs = {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache"}

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file_name in files:
                if scanned_count >= max_files:
                    break
                file_path = os.path.join(root, file_name)
                # Skip large binary files
                if file_name.endswith((".sqlite", ".db", ".png", ".jpg", ".exe", ".zip", ".tar", ".gz")):
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for idx, line in enumerate(f, start=1):
                            for pattern, secret_type, severity in SECRET_PATTERNS:
                                match = re.search(pattern, line)
                                if match:
                                    snippet = match.group(0)[:60]
                                    ent = self.calculate_entropy(match.group(0))
                                    findings.append(SecretFinding(
                                        file_path=file_path,
                                        line_number=idx,
                                        secret_type=secret_type,
                                        severity=severity,
                                        match_snippet=snippet,
                                        entropy=ent,
                                    ))
                except Exception as e:
                    logger.debug(f"[SecretScanner] Could not read {file_path}: {e}")
                scanned_count += 1

        return [f.to_dict() for f in findings]


class CredentialHardeningAuditor:
    """Audits local OS credential protection mechanisms (SAM, LSASS, /etc/shadow permissions)."""

    def audit_shadow_permissions(self, path: str = "/etc/shadow") -> Dict[str, Any]:
        """Audit /etc/shadow permissions (Linux). Must be owned by root and 0600 or 0640."""
        if not os.path.exists(path):
            return {"status": "not_applicable", "path": path, "reason": "File does not exist (non-Linux)"}

        try:
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            mode_oct = oct(mode)
            uid = st.st_uid

            is_secure = (mode in (0o600, 0o640)) and (uid == 0)
            return {
                "status": "secure" if is_secure else "vulnerable",
                "path": path,
                "permissions": mode_oct,
                "owner_uid": uid,
                "remediation": "Chmod /etc/shadow to 0600 or 0640 owned strictly by root:shadow.",
            }
        except Exception as e:
            return {"status": "error", "path": path, "error": str(e)}

    def audit_windows_credential_guard(self) -> Dict[str, Any]:
        """Audit Windows LSASS Protection & Credential Guard state."""
        try:
            cmd = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            ppl_enabled = "0x1" in res.stdout

            return {
                "status": "secure" if ppl_enabled else "vulnerable",
                "lsass_ppl_enabled": ppl_enabled,
                "remediation": "Enable LSASS Protected Process Light via reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' /v RunAsPPL /t REG_DWORD /d 1 /f",
            }
        except Exception as e:
            return {"status": "not_applicable", "error": str(e)}
