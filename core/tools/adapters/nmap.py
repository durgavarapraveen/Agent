import logging
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple

from core.domain.finding import FindingState, SecurityFinding
from core.tools.adapters.base import BaseAdapter
from core.tools.models import ExecutionStatus, ToolAttempt

logger = logging.getLogger(__name__)


class NmapAdapter(BaseAdapter):
    def __init__(self, target: str, timeout: float = 300.0):
        super().__init__(target, timeout)
        self.tool_name = "nmap"

    def execute(self, args: Dict[str, Any]) -> Tuple[ToolAttempt, List[SecurityFinding]]:
        start = time.time()

        # Prefer XML output — the previous text-regex parser only matched
        # `NN/tcp open service` lines and silently returned empty on any
        # -oG / -oX / -sU / IPv6 output. XML is stable across nmap versions.
        cmd = ["nmap", "-sV", "-oX", "-", self.target]
        if args.get("fast_mode"):
            cmd.insert(1, "-F")

        findings: List[SecurityFinding] = []
        try:
            # P0-D2: nmap lives in the Kali container, not on the host PATH
            # (always absent on Windows). Run locally only when present; otherwise
            # dispatch through KaliDockerExecutor (same scope validation as other
            # tools) instead of hard-failing "binary not found".
            if shutil.which("nmap"):
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                rc, out, err = result.returncode, result.stdout, result.stderr
            else:
                import shlex
                from agents.kali_executor import KaliDockerExecutor
                cmd_str = " ".join(shlex.quote(c) for c in cmd)
                r = KaliDockerExecutor.run(cmd_str, timeout=int(self.timeout), auto_install=True)
                rc = r.get("returncode")
                rc = rc if rc is not None else 1
                out, err = r.get("stdout", "") or "", r.get("stderr", "") or ""
            duration = (time.time() - start) * 1000

            status = ExecutionStatus.COMPLETED if rc == 0 else ExecutionStatus.FAILED
            evidence = (out or "") + "\n" + (err or "")

            if status == ExecutionStatus.COMPLETED:
                findings = self._parse_output(out)

            attempt = ToolAttempt(
                tool_name=self.tool_name,
                status=status,
                evidence=evidence,
                execution_time_ms=duration,
            )
            return attempt, findings

        except subprocess.TimeoutExpired as e:
            duration = (time.time() - start) * 1000
            return ToolAttempt(
                tool_name=self.tool_name,
                status=ExecutionStatus.TIMEOUT,
                evidence=(e.stdout.decode("utf-8", errors="replace") if e.stdout else "Timeout"),
                execution_time_ms=duration,
            ), []
        except Exception as e:
            logger.exception("nmap adapter unexpected error")
            duration = (time.time() - start) * 1000
            return ToolAttempt(
                tool_name=self.tool_name,
                status=ExecutionStatus.FAILED,
                evidence=str(e),
                execution_time_ms=duration,
            ), []

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        stdout = stdout or ""
        if stdout.lstrip().startswith("<?xml"):
            try:
                root = ET.fromstring(stdout)
                for host in root.iter("host"):
                    for port in host.iter("port"):
                        state_elem = port.find("state")
                        if state_elem is None or state_elem.get("state") != "open":
                            continue
                        port_num = port.get("portid", "?")
                        proto = port.get("protocol", "tcp")
                        service_elem = port.find("service")
                        service = (service_elem.get("name") if service_elem is not None else "unknown") or "unknown"
                        product = (service_elem.get("product") if service_elem is not None else "") or ""
                        version = (service_elem.get("version") if service_elem is not None else "") or ""
                        banner = " ".join(x for x in (product, version) if x)
                        title = f"Open Port {port_num}/{proto} ({service})"
                        desc = f"Nmap detected open port {port_num} running {service}"
                        if banner:
                            desc += f" — {banner}"
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            title=title,
                            description=desc,
                            severity="INFO",
                            finding_state=FindingState.CANDIDATE,
                        ))
                return findings
            except ET.ParseError as e:
                logger.warning("nmap XML parse failed, falling back to line regex: %s", e)

        import re as _re
        # Legacy line-parser as a last resort. `tcp|udp` and `[a-z0-9-]+`
        # widens the previous overly narrow regex.
        port_pattern = _re.compile(r"(\d+)/(tcp|udp)\s+open\s+([\w./+-]+)")
        for line in stdout.split("\n"):
            match = port_pattern.search(line)
            if match:
                port, proto, service = match.groups()
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    title=f"Open Port {port}/{proto} ({service})",
                    description=f"Nmap detected open port {port} running {service}",
                    severity="INFO",
                    finding_state=FindingState.CANDIDATE,
                ))
        return findings
