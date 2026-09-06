import logging
from typing import Dict, Any, List, Tuple
from core.tools.models import ExecutionResult, ToolAttempt, ExecutionStatus
from core.tools.capability_mapper import CapabilityMapper
from core.domain.finding import SecurityFinding

from core.tools.adapters.nmap import NmapAdapter
from core.tools.adapters.masscan import MasscanAdapter
from core.fuzzing.adapters import SQLMapAdapter, NucleiAdapter, DalfoxAdapter
from core.domain.endpoint import Endpoint

logger = logging.getLogger(__name__)

class ToolExecutor:
    def __init__(self, target: str):
        self.target = target
        self.mapper = CapabilityMapper()

    def _get_adapter(self, tool_name: str, timeout: float, args: Dict[str, Any]):
        # The fuzzer adapters take an Endpoint object instead of a string target, 
        # so we mock a generic endpoint for generalized tools that need it.
        mock_ep = Endpoint(endpoint_id="mock", path="/", url=self.target, method_set={"GET"})
        
        if tool_name == "nmap":
            return NmapAdapter(self.target, timeout)
        elif tool_name == "masscan":
            return MasscanAdapter(self.target, timeout)
        elif tool_name == "sqlmap":
            return SQLMapAdapter(mock_ep, self.target) # Repurposing fuzzing adapter
        elif tool_name == "nuclei":
            return NucleiAdapter(mock_ep, self.target)
        elif tool_name == "dalfox":
            return DalfoxAdapter(mock_ep, self.target)
        else:
            raise ValueError(f"Unsupported tool: {tool_name}")

    def execute(self, tool_name: str, args: Dict[str, Any], timeout: float = 300.0) -> Tuple[ToolAttempt, List[SecurityFinding]]:
        adapter = self._get_adapter(tool_name, timeout, args)
        
        try:
            # Handle API signature mismatch between new adapters (Tuple) and old Fuzz adapters (ToolResult)
            if hasattr(adapter, 'tool_name') and adapter.tool_name in ["sqlmap", "nuclei", "dalfox"]:
                fuzz_result = adapter.execute(args)
                # Map old ToolResult back to new ToolAttempt structure for tracking
                return ToolAttempt(
                    tool_name=tool_name,
                    status=ExecutionStatus(fuzz_result.status.value),
                    evidence=fuzz_result.evidence,
                    execution_time_ms=fuzz_result.execution_time_ms
                ), fuzz_result.findings
            else:
                return adapter.execute(args)
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return ToolAttempt(
                tool_name=tool_name,
                status=ExecutionStatus.FAILED,
                evidence=str(e)
            ), []

    def execute_with_fallback(self, capability: str, args: Dict[str, Any]) -> ExecutionResult:
        tools = self.mapper.get_tools_for_capability(capability)
        result = ExecutionResult(capability=capability, target=self.target)
        
        if not tools:
            logger.warning(f"No tools mapped for capability: {capability}")
            result.status = ExecutionStatus.FAILED
            return result

        for tool_name in tools:
            logger.info(f"Attempting capability '{capability}' with tool '{tool_name}'")
            attempt, findings = self.execute(tool_name, args)
            result.attempts.append(attempt)
            logger.debug(
                "tool=%s returned status=%s with evidence=%s",
                tool_name, attempt.status, attempt.evidence,
            )
            
            if attempt.status == ExecutionStatus.COMPLETED or attempt.status == "success": # string matching for older fuzzer status
                result.status = ExecutionStatus.COMPLETED
                result.findings.extend(findings)
                return result
            else:
                logger.warning(f"Tool {tool_name} failed/timed out. Trying fallback...")

        result.status = ExecutionStatus.FAILED
        return result
