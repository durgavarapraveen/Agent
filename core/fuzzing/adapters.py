import subprocess
import json
import uuid
import logging
from typing import Dict, Any, List
import time

from core.domain.endpoint import Endpoint
from core.domain.finding import SecurityFinding, FindingState
from core.fuzzing.models import ToolResult, ToolStatus

logger = logging.getLogger(__name__)

class BaseAdapter:
    def __init__(self, endpoint: Endpoint, target: str):
        self.endpoint = endpoint
        self.target = target
        self.tool_name = "base"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        raise NotImplementedError()

class SQLMapAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "sqlmap"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        cmd = [
            "sqlmap",
            "-u", self.endpoint.url,
            "--batch",
            "--dbs"
        ]
        
        # Additional params from config
        if params.get("tamper"):
            cmd.extend(["--tamper", params["tamper"]])
        if params.get("threads"):
            cmd.extend(["--threads", str(params["threads"])])
            
        start = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
            duration = (time.time() - start) * 1000
            
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.ERROR
            findings = self._parse_output(result.stdout)
            
            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                findings=findings,
                evidence=result.stdout,
                execution_time_ms=duration
            )
            
        except subprocess.TimeoutExpired as e:
            logger.warning(f"SQLMap timed out on {self.endpoint.url}")
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                evidence=e.stdout.decode() if e.stdout else "",
                execution_time_ms=30000.0
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e),
                execution_time_ms=(time.time() - start) * 1000
            )

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings = []
        if "Parameter:" in stdout and "is vulnerable" in stdout:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="SQL Injection Detected",
                description="SQLMap detected a vulnerable parameter.",
                severity="CRITICAL",
                endpoint_id=self.endpoint.endpoint_id,
                state=FindingState.OPEN,
                evidence={"output": stdout}
            ))
        return findings


class NucleiAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "nuclei"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        cmd = [
            "nuclei",
            "-u", self.endpoint.url,
            "-json-export", "-" # output json to stdout
        ]
        
        if params.get("template"):
            cmd.extend(["-t", params["template"]])
        if params.get("rate_limit"):
            cmd.extend(["-rl", str(params["rate_limit"])])
            
        start = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
            duration = (time.time() - start) * 1000
            
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.ERROR
            findings = self._parse_output(result.stdout)
            
            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                findings=findings,
                evidence=result.stdout,
                execution_time_ms=duration
            )
        except subprocess.TimeoutExpired as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                evidence=e.stdout.decode() if e.stdout else "",
                execution_time_ms=30000.0
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e)
            )
            
    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings = []
        lines = stdout.strip().split("\n")
        for line in lines:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if "info" in data:
                    findings.append(SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        title=data["info"].get("name", "Nuclei Finding"),
                        description=data["info"].get("description", ""),
                        severity=str(data["info"].get("severity", "MEDIUM")).upper(),
                        endpoint_id=self.endpoint.endpoint_id,
                        state=FindingState.OPEN,
                        evidence=data
                    ))
            except json.JSONDecodeError:
                pass
        return findings

class DalfoxAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "dalfox"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        cmd = [
            "dalfox", "url", self.endpoint.url
        ]
        
        if params.get("concurrency"):
            cmd.extend(["-w", str(params["concurrency"])])
            
        start = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
            duration = (time.time() - start) * 1000
            
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.ERROR
            findings = self._parse_output(result.stdout)
            
            return ToolResult(
                tool_name=self.tool_name,
                status=status,
                findings=findings,
                evidence=result.stdout,
                execution_time_ms=duration
            )
        except subprocess.TimeoutExpired as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.TIMEOUT,
                evidence=e.stdout.decode() if e.stdout else "",
                execution_time_ms=30000.0
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_name,
                status=ToolStatus.ERROR,
                evidence=str(e)
            )

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings = []
        if "[V]" in stdout or "[G]" in stdout:
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title="XSS Detected by Dalfox",
                description="Dalfox identified a reflected or stored XSS payload.",
                severity="HIGH",
                endpoint_id=self.endpoint.endpoint_id,
                state=FindingState.OPEN,
                evidence={"output": stdout}
            ))
        return findings
