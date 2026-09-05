"""
Persistence Vector Monitor & Defensive Rule Generator.
Audits Windows Scheduled Tasks (Event ID 4698), Linux Cron/Systemd timers, SSH keys,
Web Shell File Integrity Monitoring (FIM), and generates Sigma YAML & Auditd rules.
"""

import logging
import os
import re
import stat
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

SIGMA_TASK_CREATION_RULE = """title: Scheduled Task Created for Persistence (Event 4698)
id: 4698-scheduled-task-creation
status: experimental
description: Detects scheduled task creations executing script interpreters or non-standard binaries.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
        Command|contains:
            - 'powershell.exe'
            - 'cmd.exe'
            - 'wscript.exe'
            - 'cscript.exe'
            - 'mshta.exe'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: high
"""

AUDITD_CRON_RULE = """# Auditd rules for monitoring persistence in Cron & Systemd Timers
-w /etc/cron.default/ -p wa -k cron_persistence
-w /etc/cron.daily/ -p wa -k cron_persistence
-w /etc/cron.hourly/ -p wa -k cron_persistence
-w /etc/cron.monthly/ -p wa -k cron_persistence
-w /etc/cron.weekly/ -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence
-w /var/spool/cron/crontabs/ -p wa -k cron_persistence
-w /etc/systemd/system/ -p wa -k systemd_persistence
"""


class PersistenceMonitor:
    """Audits persistence vectors and generates actionable SIEM / Auditd defensive rules."""

    def __init__(self, web_root: str = "/var/www/html"):
        self.web_root = web_root

    def generate_sigma_rules(self) -> str:
        """Return Sigma YAML rule specification for Windows Event 4698 (Scheduled Tasks)."""
        return SIGMA_TASK_CREATION_RULE.strip()

    def generate_auditd_rules(self) -> str:
        """Return Linux Auditd rule specification for Cron and Systemd Timers."""
        return AUDITD_CRON_RULE.strip()

    def audit_ssh_authorized_keys(self, ssh_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Audit permissions and integrity of ~/.ssh/authorized_keys."""
        findings = []
        target_dir = ssh_dir or os.path.expanduser("~/.ssh")
        auth_keys_path = os.path.join(target_dir, "authorized_keys")

        if not os.path.exists(auth_keys_path):
            return findings

        try:
            st = os.stat(auth_keys_path)
            mode = stat.S_IMODE(st.st_mode)

            if mode not in (0o600, 0o400):
                findings.append({
                    "category": "ssh_persistence",
                    "title": "Permissive SSH authorized_keys Permissions",
                    "severity": "HIGH",
                    "path": auth_keys_path,
                    "permissions": oct(mode),
                    "remediation": f"Chmod {auth_keys_path} to 0600 (read/write by owner only).",
                })

            with open(auth_keys_path, "r", encoding="utf-8", errors="ignore") as f:
                keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                findings.append({
                    "category": "ssh_inventory",
                    "title": f"SSH Authorized Keys Inventory ({len(keys)} keys found)",
                    "severity": "INFO",
                    "path": auth_keys_path,
                    "key_count": len(keys),
                    "remediation": "Regularly audit authorized_keys to remove stale or unapproved public keys.",
                })
        except Exception as e:
            logger.debug(f"[PersistenceMonitor] SSH audit failed: {e}")

        return findings

    def audit_webshell_fim(self, search_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """File Integrity Monitoring (FIM) check on web root for suspicious web shell scripts."""
        findings = []
        target_root = search_dir or self.web_root

        if not os.path.exists(target_root):
            return findings

        webshell_signatures = [
            r"eval\s*\(\s*base64_decode",
            r"system\s*\(\s*\$_POST",
            r"passthru\s*\(",
            r"shell_exec\s*\(",
            r"cmd\.exe\s+/c",
            r"ProcessBuilder",
            r"Runtime\.getRuntime\(\)\.exec",
        ]

        webshell_exts = {".php", ".aspx", ".jsp", ".phtml", ".cgi"}

        for root, _, files in os.walk(target_root):
            for file_name in files:
                _, ext = os.path.splitext(file_name)
                if ext.lower() in webshell_exts:
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for sig in webshell_signatures:
                                if re.search(sig, content, re.IGNORECASE):
                                    findings.append({
                                        "category": "webshell_fim",
                                        "title": f"Potential Web Shell Detected: {file_name}",
                                        "severity": "CRITICAL",
                                        "file_path": file_path,
                                        "matched_signature": sig,
                                        "remediation": "Isolate the host, quarantine the file, and review web server access logs for HTTP POST requests to this script.",
                                    })
                                    break
                    except Exception as e:
                        logger.debug(f"[PersistenceMonitor] FIM read error on {file_path}: {e}")

        return findings
