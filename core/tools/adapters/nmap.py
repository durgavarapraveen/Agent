import subprocess
import time
import uuid
import re
from typing import Dict, Any, Tuple, List
from core.tools.adapters.base import BaseAdapter
from core.tools.models import ToolAttempt, ExecutionStatus
from core.domain.finding import SecurityFinding, FindingState

class NmapAdapter(BaseAdapter):
    def __init__(self, target: str, timeout: float = 300.0):
        super().__init__(target, timeout)
        self.tool_name = "nmap"

    def execute(self, args: Dict[str, Any]) -> Tuple[ToolAttempt, List[SecurityFinding]]:
        cmd = ["nmap", "-sV", self.target]
        if args.get("fast_mode"):
            cmd.insert(1, "-F")
            
        start = time.time()
        findings = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            duration = (time.time() - start) * 1000
            
            status = ExecutionStatus.COMPLETED if result.returncode == 0 else ExecutionStatus.FAILED
            evidence = result.stdout + "\n" + result.stderr
            
            if status == ExecutionStatus.COMPLETED:
                findings = self._parse_output(result.stdout)
                
            attempt = ToolAttempt(
                tool_name=self.tool_name,
                status=status,
                evidence=evidence,
                execution_time_ms=duration
            )
            return attempt, findings
            
        except subprocess.TimeoutExpired as e:
            duration = (time.time() - start) * 1000
            return ToolAttempt(
                tool_name=self.tool_name,
                status=ExecutionStatus.TIMEOUT,
                evidence=e.stdout.decode('utf-8') if e.stdout else "Timeout",
                execution_time_ms=duration
            ), []
        except Exception as e:
            print(f"NMAP EXCEPTION: {e}")
            duration = (time.time() - start) * 1000
            return ToolAttempt(
                tool_name=self.tool_name,
                status=ExecutionStatus.FAILED,
                evidence=str(e),
                execution_time_ms=duration
            ), []

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings = []
        # Basic parsing for "80/tcp open http"
        port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\S+)")
        for line in stdout.split('\n'):
            match = port_pattern.search(line)
            if match:
                port = match.group(1)
                service = match.group(2)
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    title=f"Open Port {port}/tcp ({service})",
                    description=f"Nmap detected open port {port} running {service}",
                    severity="INFO",
                    finding_state=FindingState.CANDIDATE
                ))
        return findings
