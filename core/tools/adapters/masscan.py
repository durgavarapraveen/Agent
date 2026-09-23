import shutil
import subprocess
import time
from typing import Dict, Any, Tuple, List
from core.tools.adapters.base import BaseAdapter
from core.tools.models import ToolAttempt, ExecutionStatus
from core.domain.finding import SecurityFinding

class MasscanAdapter(BaseAdapter):
    def __init__(self, target: str, timeout: float = 120.0):
        super().__init__(target, timeout)
        self.tool_name = "masscan"

    def execute(self, args: Dict[str, Any]) -> Tuple[ToolAttempt, List[SecurityFinding]]:
        cmd = ["masscan", "-p1-65535", self.target, "--rate", str(args.get("rate", 1000))]

        start = time.time()
        try:
            # P0-D2: masscan lives in the Kali container, not on the host PATH
            # (always absent on Windows). Dispatch through KaliDockerExecutor when
            # it isn't local instead of erroring out.
            if shutil.which("masscan"):
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

            attempt = ToolAttempt(
                tool_name=self.tool_name,
                status=status,
                evidence=(out or "") + "\n" + (err or ""),
                execution_time_ms=duration
            )
            # Simplification: we let Nmap fallback do the heavy parsing if we mock failure here
            return attempt, []
            
        except subprocess.TimeoutExpired as e:
            duration = (time.time() - start) * 1000
            return ToolAttempt(
                tool_name=self.tool_name,
                status=ExecutionStatus.TIMEOUT,
                evidence="Timeout",
                execution_time_ms=duration
            ), []
        except Exception as e:
            duration = (time.time() - start) * 1000
            return ToolAttempt(
                tool_name=self.tool_name,
                status=ExecutionStatus.FAILED,
                evidence=str(e),
                execution_time_ms=duration
            ), []
