import subprocess
import shutil
import json
import uuid
import logging
from typing import Dict, Any, List
import time

from core.domain.endpoint import Endpoint
from core.domain.finding import SecurityFinding, FindingState
from core.fuzzing.models import ToolResult, ToolStatus

logger = logging.getLogger(__name__)


def _tool_available(binary: str) -> bool:
    """Cheap preflight — cache is provided by shutil.which itself on Linux."""
    return shutil.which(binary) is not None


def _missing_binary_result(tool: str, binary: str, start: float) -> ToolResult:
    """Distinguishable result for a missing binary. Previously every adapter
    caught `FileNotFoundError` inside its generic `except Exception` and
    returned an indistinguishable ERROR — operators couldn't tell whether
    the tool was misconfigured or the target was refusing connections."""
    duration = (time.time() - start) * 1000
    logger.warning("Tool binary not found: %s (%s)", tool, binary)
    return ToolResult(
        tool_name=tool,
        status=ToolStatus.ERROR,
        findings=[],
        evidence=f"binary_not_found:{binary}",
        execution_time_ms=duration,
    )


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
        start = time.time()
        if not _tool_available("sqlmap"):
            return _missing_binary_result(self.tool_name, "sqlmap", start)

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

    # sqlmap prints per-parameter blocks like:
    #   Parameter: id (GET)
    #       Type: boolean-based blind
    #       Title: AND boolean-based blind - WHERE or HAVING clause
    #       Payload: id=1 AND 1=1
    # A block is only a real finding if it contains BOTH `Parameter:` and
    # at least one of the confirmation markers. The previous substring
    # check accepted any stdout that happened to include those keywords
    # anywhere, including sqlmap's own banner text.
    _SQLMAP_CONFIRMATION_MARKERS = (
        "the following injection point",
        "sqlmap identified the following injection point",
        "type:",
        "payload:",
        "target url appears to be UNION injectable",
    )

    def _parse_output(self, stdout: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        import re as _re_sql
        # Find each `Parameter: <name> (<method>)` block and verify at least
        # one confirmation marker appears within its slice.
        param_iter = list(_re_sql.finditer(
            r"Parameter:\s+([\w\[\]#-]+)\s+\((GET|POST|COOKIE|HEADER|URI)\)",
            stdout,
        ))
        for i, m in enumerate(param_iter):
            start = m.end()
            end = param_iter[i + 1].start() if i + 1 < len(param_iter) else len(stdout)
            block = stdout[start:end]
            low_block = block.lower()
            if not any(marker in low_block for marker in self._SQLMAP_CONFIRMATION_MARKERS):
                continue
            param_name = m.group(1)
            method = m.group(2)
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title=f"SQL Injection in {method} parameter '{param_name}'",
                description=("SQLMap detected an injectable parameter with at least "
                              "one confirmation marker in its output block."),
                severity="CRITICAL",
                endpoint_id=self.endpoint.endpoint_id,
                state=FindingState.CANDIDATE,
                evidence={"parameter": param_name, "method": method, "output": block[:2000]},
            ))
        return findings


class NucleiAdapter(BaseAdapter):
    def __init__(self, endpoint: Endpoint, target: str):
        super().__init__(endpoint, target)
        self.tool_name = "nuclei"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        start = time.time()
        if not _tool_available("nuclei"):
            return _missing_binary_result(self.tool_name, "nuclei", start)

        cmd = [
            "nuclei",
            "-u", self.endpoint.url,
            "-json-export", "-" # output json to stdout
        ]

        if params.get("template"):
            cmd.extend(["-t", params["template"]])
        if params.get("rate_limit"):
            cmd.extend(["-rl", str(params["rate_limit"])])

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
                        state=FindingState.CANDIDATE,
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
        start = time.time()
        if not _tool_available("dalfox"):
            return _missing_binary_result(self.tool_name, "dalfox", start)

        cmd = [
            "dalfox", "url", self.endpoint.url
        ]

        if params.get("concurrency"):
            cmd.extend(["-w", str(params["concurrency"])])

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
        """Parse dalfox stdout for confirmed and grep findings.

        Dalfox prints one line per finding:
            [V] URL  -- confirmed vulnerable (payload triggered)
            [G] URL  -- grep-based match (weak signal, may be FP)
        Emit ONE finding per line so downstream dedup can score them
        individually. The previous "any `[V]` or `[G]` anywhere → one
        finding" collapsed dozens of real hits into a single entry.
        """
        findings: List[SecurityFinding] = []
        import re as _re_dx
        for m in _re_dx.finditer(r"^\s*\[(V|G|R)\]\s+(\S+)(.*)$", stdout, _re_dx.MULTILINE):
            tag, url, tail = m.group(1), m.group(2), (m.group(3) or "").strip()
            if tag == "V":
                severity = "HIGH"
                title = f"XSS confirmed by Dalfox on {url}"
            elif tag == "G":
                severity = "MEDIUM"  # grep-based, weaker signal
                title = f"XSS candidate (grep-match) by Dalfox on {url}"
            else:  # 'R' = reflected but not proven
                severity = "LOW"
                title = f"Dalfox reflected marker on {url}"
            findings.append(SecurityFinding(
                finding_id=str(uuid.uuid4()),
                title=title,
                description="Dalfox reported a signal against the parameter.",
                severity=severity,
                endpoint_id=self.endpoint.endpoint_id,
                state=FindingState.CANDIDATE,
                evidence={"tag": tag, "url": url, "detail": tail[:400]},
            ))
        return findings
