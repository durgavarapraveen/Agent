
import logging
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class ExposureFinding:
    category: str
    title: str
    severity: str
    description: str
    host: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "host": self.host,
            "details": self.details,
            "remediation": self.remediation,
        }


class NetworkAuditor:

    def __init__(self, target_host: str = "localhost"):
        self.target_host = target_host

    def audit_smb_exposure(self, host: Optional[str] = None) -> List[ExposureFinding]:
        target = host or self.target_host
        findings: List[ExposureFinding] = []

        # 1. Check SMB Port (445) Availability
        smb_open = self._check_port(target, 445)
        if smb_open:
            findings.append(ExposureFinding(
                category="smb_exposure",
                title="SMB Service Exposed (Port 445)",
                severity="MEDIUM",
                description=f"SMB port 445 is open on {target}.",
                host=target,
                details={"port": 445, "status": "open"},
                remediation="Ensure host-based firewalls restrict SMB access to authorized administrative networks only."
            ))

        # 2. Check PowerShell SMB Configuration (Windows Native Check)
        try:
            cmd = [
                "powershell", "-Command",
                "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature | ConvertTo-Json"
            ]
            res = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                import json
                data = json.loads(res.stdout)
                smb1_enabled = data.get("EnableSMB1Protocol", False)
                signing_required = data.get("RequireSecuritySignature", False)

                if smb1_enabled:
                    findings.append(ExposureFinding(
                        category="smb_exposure",
                        title="Legacy SMBv1 Protocol Enabled",
                        severity="HIGH",
                        description=f"Host {target} has legacy SMBv1 protocol enabled.",
                        host=target,
                        details={"smb1_enabled": True},
                        remediation="Disable SMBv1 immediately via GPO or Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol."
                    ))

                if not signing_required:
                    findings.append(ExposureFinding(
                        category="smb_exposure",
                        title="SMB Signing Not Enforced",
                        severity="HIGH",
                        description=f"SMB Signing is not required on {target}, allowing potential NTLM relay attacks.",
                        host=target,
                        details={"require_signing": False},
                        remediation="Enforce SMB Signing via GPO: 'Microsoft network server: Digitally sign communications (always)'."
                    ))
        except Exception as e:
            logger.debug(f"[NetworkAuditor] Powershell SMB check skipped: {e}")

        return findings

    def audit_pivot_risks(self) -> List[ExposureFinding]:
        findings: List[ExposureFinding] = []
        try:
            # Check local network interfaces
            addrs = socket.getaddrinfo(socket.gethostname(), None)
            ips = sorted(set(r[4][0] for r in addrs if ":" not in r[4][0] and not r[4][0].startswith("127.")))

            subnets = set()
            for ip in ips:
                parts = ip.split(".")
                if len(parts) == 4:
                    subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

            if len(subnets) > 1:
                findings.append(ExposureFinding(
                    category="pivot_risk",
                    title="Dual-Homed Host Detected (Multiple Subnets)",
                    severity="HIGH",
                    description=f"Host is connected to multiple distinct subnets: {sorted(subnets)}.",
                    host=socket.gethostname(),
                    details={"interfaces": ips, "subnets": sorted(subnets)},
                    remediation="Audit multi-homed routing paths and verify EDR monitoring on network pivoting endpoints."
                ))
        except Exception as e:
            logger.debug(f"[NetworkAuditor] Pivot risk audit failed: {e}")

        return findings

    def run_full_audit(self) -> List[Dict[str, Any]]:
        all_findings = []
        all_findings.extend([f.to_dict() for f in self.audit_smb_exposure()])
        all_findings.extend([f.to_dict() for f in self.audit_pivot_risks()])
        return all_findings

    def _check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            s.close()
            return res == 0
        except Exception:
            return False
