"""
Privilege Escalation Chain Detector (Phase 3, Module 1)

Detects local privilege-escalation opportunities on a compromised host:
  - Kernel exploit opportunities (version -> known CVE hints)
  - SUID binary abuse paths (GTFOBins)
  - sudo misconfigurations
  - Recommends the best escalation path

Analysis-only by default. Active enumeration runs ONLY when a `runner`
(async command executor) is supplied by the caller AND the tier permits it;
otherwise the detector just returns the enumeration plan + static reasoning.
"""

import logging
import re
from typing import Callable, Dict, List, Optional, Awaitable
from dataclasses import dataclass, field

from agents.llm_client import LLMClient, TaskTier

logger = logging.getLogger(__name__)

# Commands used to enumerate a Linux host for privesc vectors (read-only).
ENUM_COMMANDS = {
    "whoami":       "id; whoami",
    "kernel":       "uname -a; cat /etc/os-release 2>/dev/null | head -5",
    "suid":         "find / -perm -4000 -type f 2>/dev/null",
    "sudo":         "sudo -n -l 2>/dev/null",
    "capabilities": "getcap -r / 2>/dev/null",
    "cron":         "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
    "writable":     "find / -writable -type d 2>/dev/null | head -20",
    "processes":    "ps aux 2>/dev/null | head -40",
}

# GTFOBins-style SUID binaries that trivially yield a root shell / file read.
GTFOBINS_SUID = {
    "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv",
    "awk", "gawk", "perl", "python", "python3", "ruby", "php", "node",
    "env", "tar", "zip", "socat", "systemctl", "dpkg", "apt", "man",
    "wget", "curl", "docker", "ftp", "gdb", "make", "vi", "ed", "tee",
}

# Kernel version -> well-known local root exploit hints (advisory only).
KERNEL_EXPLOIT_HINTS = [
    ("2.6.", "DirtyCOW (CVE-2016-5195)"),
    ("3.", "DirtyCOW (CVE-2016-5195) / overlayfs"),
    ("4.4", "DirtyCOW / af_packet (CVE-2017-7308)"),
    ("4.8", "overlayfs (CVE-2017-1000112)"),
    ("5.8", "DirtyPipe (CVE-2022-0847)"),
    ("5.10", "DirtyPipe (CVE-2022-0847)"),
    ("5.11", "DirtyPipe (CVE-2022-0847)"),
    ("5.13", "PwnKit (CVE-2021-4034) userspace / nf_tables (CVE-2022-32250)"),
]

CmdRunner = Callable[[str], Awaitable[str]]


@dataclass
class PrivescFinding:
    """A single privilege-escalation opportunity."""
    host: str
    technique: str                 # kernel_exploit | suid_abuse | sudo_misconfig | capability
    detail: str
    escalation_path: str = ""
    severity: str = "MEDIUM"        # LOW / MEDIUM / HIGH / CRITICAL
    confidence: float = 0.5
    mitre_id: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict:
        return {
            "host": self.host, "technique": self.technique, "detail": self.detail,
            "path": self.escalation_path, "severity": self.severity,
            "confidence": self.confidence, "mitre_id": self.mitre_id,
            "evidence": self.evidence[:300],
        }


class PrivescDetector:
    """Finds and ranks local privilege-escalation paths on a host."""

    def __init__(self, tier: str = "POC"):
        self.llm = LLMClient.get()
        self.tier = (tier or "POC").upper()
        self.findings: List[PrivescFinding] = []

    def enumeration_plan(self) -> Dict[str, str]:
        """Read-only commands the caller can run to enumerate privesc vectors."""
        return dict(ENUM_COMMANDS)

    async def analyze(self, host: str = "target", enum_output: str = "",
                      runner: Optional[CmdRunner] = None) -> List[PrivescFinding]:
        """
        Analyze a host for privesc paths.

        If `runner` is provided the read-only ENUM_COMMANDS are executed to
        gather live data; otherwise `enum_output` (or nothing) is analyzed.
        """
        outputs: Dict[str, str] = {}
        if runner and self.tier in ("SHALLOW", "DEEP"):
            for name, cmd in ENUM_COMMANDS.items():
                try:
                    outputs[name] = (await runner(cmd)) or ""
                except Exception as e:      # noqa: BLE001
                    logger.debug(f"[Privesc] enum '{name}' failed: {e}")
            enum_output = "\n".join(f"### {k}\n{v}" for k, v in outputs.items())

        findings: List[PrivescFinding] = []
        findings += self._detect_suid(host, outputs.get("suid", enum_output))
        findings += self._detect_kernel(host, outputs.get("kernel", enum_output))
        findings += self._detect_sudo(host, outputs.get("sudo", enum_output))

        # LLM refinement / ranking when we have real output
        if enum_output.strip():
            findings += await self._llm_analyze(host, enum_output)

        # Dedup by (technique, detail)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.technique, f.detail[:60])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        deduped.sort(key=lambda f: (self._sev_rank(f.severity), f.confidence), reverse=True)
        self.findings = deduped
        logger.info(f"[Privesc] {host}: {len(deduped)} escalation paths found")
        return deduped

    # ── static detectors ──

    def _detect_suid(self, host: str, text: str) -> List[PrivescFinding]:
        out = []
        for line in (text or "").splitlines():
            binary = line.strip().split("/")[-1]
            if binary in GTFOBINS_SUID:
                out.append(PrivescFinding(
                    host=host, technique="suid_abuse",
                    detail=f"SUID {binary} is GTFOBins-abusable",
                    escalation_path=f"Use SUID '{binary}' to spawn a root shell "
                                    f"(see GTFOBins '{binary}' SUID section)",
                    severity="HIGH", confidence=0.8,
                    mitre_id="T1548.001", evidence=line.strip(),
                ))
        return out

    def _detect_kernel(self, host: str, text: str) -> List[PrivescFinding]:
        out = []
        m = re.search(r"\b(\d+\.\d+[\.\d]*)", text or "")
        version = m.group(1) if m else ""
        for prefix, hint in KERNEL_EXPLOIT_HINTS:
            if version.startswith(prefix):
                out.append(PrivescFinding(
                    host=host, technique="kernel_exploit",
                    detail=f"Kernel {version} may be vulnerable to {hint}",
                    escalation_path=f"Compile/run {hint} local root exploit "
                                    f"(verify build tools present first)",
                    severity="CRITICAL", confidence=0.55,
                    mitre_id="T1068", evidence=f"kernel {version}",
                ))
                break
        return out

    def _detect_sudo(self, host: str, text: str) -> List[PrivescFinding]:
        out = []
        t = (text or "").lower()
        if "(all : all)" in t or "(all) all" in t or "nopasswd: all" in t:
            out.append(PrivescFinding(
                host=host, technique="sudo_misconfig",
                detail="sudo allows running ALL commands (optionally NOPASSWD)",
                escalation_path="sudo su - / sudo -s for an immediate root shell",
                severity="CRITICAL", confidence=0.9,
                mitre_id="T1548.003", evidence=text.strip()[:200],
            ))
        for m in re.finditer(r"nopasswd:\s*([^\n]+)", t):
            binp = m.group(1).strip()
            if "all" not in binp:
                out.append(PrivescFinding(
                    host=host, technique="sudo_misconfig",
                    detail=f"NOPASSWD sudo on: {binp}",
                    escalation_path=f"Abuse '{binp}' via GTFOBins sudo section to escalate",
                    severity="HIGH", confidence=0.75,
                    mitre_id="T1548.003", evidence=binp,
                ))
        return out

    async def _llm_analyze(self, host: str, enum_output: str) -> List[PrivescFinding]:
        prompt = f"""You are the privilege-escalation analysis module of an AUTHORIZED
security scanner. Analyze this Linux enumeration output for local root paths.

HOST: {host}
ENUMERATION OUTPUT (truncated):
{enum_output[:4000]}

Identify concrete escalation opportunities (kernel, SUID, sudo, capabilities,
writable paths, cron). Return JSON:
{{
  "findings": [
    {{"technique": "kernel_exploit|suid_abuse|sudo_misconfig|capability|cron_abuse",
      "detail": "what is wrong",
      "escalation_path": "concrete steps to get root",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "confidence": 0.0-1.0}}
  ]
}}"""
        res = await self.llm.generate_json(prompt, tier=TaskTier.LARGE)
        out = []
        if res and isinstance(res.get("findings"), list):
            for f in res["findings"]:
                out.append(PrivescFinding(
                    host=host,
                    technique=f.get("technique", "unknown"),
                    detail=f.get("detail", ""),
                    escalation_path=f.get("escalation_path", ""),
                    severity=str(f.get("severity", "MEDIUM")).upper(),
                    confidence=float(f.get("confidence", 0.5) or 0.5),
                ))
        return out

    @staticmethod
    def _sev_rank(sev: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get((sev or "").upper(), 0)

    def recommend(self) -> Optional[PrivescFinding]:
        """Return the single best escalation path (highest sev × confidence)."""
        return self.findings[0] if self.findings else None
