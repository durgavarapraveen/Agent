"""
Structured error classification and retry policy.
Replace failed_tools set with deterministic error handling.
"""

import logging
from typing import Dict, Optional
from core.schemas import ErrorType, ErrorInfo

logger = logging.getLogger(__name__)


# Retry policy per error type
RETRY_POLICY = {
    ErrorType.COMMAND_SYNTAX_ERROR: {
        "retryable": True,
        "max_retries": 2,
        "reason": "May be fixable with corrected command"
    },
    ErrorType.INVALID_ARGUMENT: {
        "retryable": True,
        "max_retries": 2,
        "reason": "May be fixable with corrected arguments"
    },
    ErrorType.TIMEOUT: {
        "retryable": True,
        "max_retries": 3,
        "reason": "Network/resource timeout may be temporary"
    },
    ErrorType.NETWORK_ERROR: {
        "retryable": True,
        "max_retries": 3,
        "reason": "Network issues may resolve"
    },
    ErrorType.TOOL_UNAVAILABLE: {
        "retryable": False,
        "max_retries": 0,
        "reason": "Tool not installed - use alternative or install"
    },
    ErrorType.PERMISSION_DENIED: {
        "retryable": False,
        "max_retries": 0,
        "reason": "Permission denied - cannot retry"
    },
    ErrorType.SCOPE_VIOLATION: {
        "retryable": False,
        "max_retries": 0,
        "reason": "Authorization issue - never retry automatically"
    },
    ErrorType.DEPENDENCY_MISSING: {
        "retryable": True,
        "max_retries": 1,
        "reason": "Dependency missing - may install and retry"
    },
    ErrorType.EXECUTION_ERROR: {
        "retryable": True,
        "max_retries": 1,
        "reason": "Execution error may be transient"
    },
    ErrorType.PARSE_ERROR: {
        "retryable": False,
        "max_retries": 0,
        "reason": "Parse error - data malformed"
    },
    ErrorType.POLICY_REJECTION: {
        "retryable": False,
        "max_retries": 0,
        "reason": "Policy rejected - never retry"
    },
    ErrorType.UNKNOWN: {
        "retryable": True,
        "max_retries": 1,
        "reason": "Unknown error - limited retry"
    }
}


class ErrorClassifier:
    """Classify tool errors and determine retry behavior"""
    
    def classify_error(self, 
                      tool_name: str,
                      exit_code: Optional[int],
                      stdout: str,
                      stderr: str,
                      command: Optional[str] = None) -> ErrorInfo:
        """
        Classify tool execution error into structured error type.
        Uses exit code, output patterns, command analysis.
        """
        
        # Check exit code patterns
        if exit_code is None:
            return self._create_error(ErrorType.UNKNOWN, "No exit code returned")
        
        if exit_code == 124:
            return self._create_error(ErrorType.TIMEOUT, "Timeout (exit code 124)")
        
        if exit_code == 127:
            return self._create_error(ErrorType.TOOL_UNAVAILABLE, f"Tool not found: {tool_name}")
        
        if exit_code == 126:
            return self._create_error(ErrorType.PERMISSION_DENIED, "Permission denied")
        
        # Check stderr patterns
        if stderr:
            if "not found" in stderr.lower() and "command" in stderr.lower():
                return self._create_error(ErrorType.TOOL_UNAVAILABLE, stderr[:200])
            
            if "No such file" in stderr or "does not exist" in stderr:
                return self._create_error(ErrorType.DEPENDENCY_MISSING, stderr[:200])
            
            if "permission" in stderr.lower() or "denied" in stderr.lower():
                return self._create_error(ErrorType.PERMISSION_DENIED, stderr[:200])
            
            if "timeout" in stderr.lower() or "timed out" in stderr.lower():
                return self._create_error(ErrorType.TIMEOUT, stderr[:200])
            
            if "connection" in stderr.lower() or "network" in stderr.lower():
                return self._create_error(ErrorType.NETWORK_ERROR, stderr[:200])
            
            if "syntax error" in stderr.lower():
                return self._create_error(ErrorType.COMMAND_SYNTAX_ERROR, stderr[:200])
        
        # Check for command-level issues
        if command:
            if self._is_package_installation_attempt(command):
                return self._create_error(ErrorType.POLICY_REJECTION, 
                                         "Package installation blocked by policy")
        
        # Check stdout for parse errors
        if stdout and self._looks_like_parse_error(stdout):
            return self._create_error(ErrorType.PARSE_ERROR, "Failed to parse output")
        
        # General command execution error
        if exit_code != 0:
            return self._create_error(ErrorType.EXECUTION_ERROR, f"Exit code {exit_code}")
        
        return self._create_error(ErrorType.UNKNOWN, "Unknown error state")
    
    def _create_error(self, error_type: ErrorType, message: str) -> ErrorInfo:
        """Create ErrorInfo object"""
        return ErrorInfo(
            error_type=error_type,
            message=message,
            retryable=RETRY_POLICY[error_type]["retryable"],
        )
    
    def _is_package_installation_attempt(self, command: str) -> bool:
        """Detect package manager commands"""
        install_patterns = [
            "apt-get install",
            "apt install",
            "pip install",
            "npm install",
            "yum install",
            "pacman -S",
        ]
        command_lower = command.lower()
        return any(pattern in command_lower for pattern in install_patterns)
    
    def _looks_like_parse_error(self, output: str) -> bool:
        """Heuristic to detect parse/format errors"""
        if len(output) < 10:
            return True
        if output.startswith("Error:") or output.startswith("ERROR:"):
            return True
        return False
    
    def should_retry(self, error: ErrorInfo, attempt_count: int) -> bool:
        """Determine if error should trigger retry"""
        if not error.retryable:
            return False
        
        max_retries = RETRY_POLICY[error.error_type]["max_retries"]
        if attempt_count >= max_retries:
            return False
        
        return True
    
    def get_recovery_suggestion(self, error: ErrorInfo) -> str:
        """Suggest recovery action for error"""
        policy = RETRY_POLICY.get(error.error_type, {})
        
        suggestions = {
            ErrorType.TOOL_UNAVAILABLE: f"Install {error.tool} or use alternative tool",
            ErrorType.COMMAND_SYNTAX_ERROR: "Fix command syntax",
            ErrorType.INVALID_ARGUMENT: "Correct arguments",
            ErrorType.TIMEOUT: "Increase timeout or reduce scope",
            ErrorType.NETWORK_ERROR: "Check network connectivity",
            ErrorType.PERMISSION_DENIED: "Check authorization scope",
            ErrorType.SCOPE_VIOLATION: "Verify target is authorized",
            ErrorType.DEPENDENCY_MISSING: f"Install dependency: {error.details.get('dependency')}",
            ErrorType.EXECUTION_ERROR: "Review command and try again",
            ErrorType.PARSE_ERROR: "Check tool output format",
            ErrorType.POLICY_REJECTION: "Action blocked by policy",
            ErrorType.UNKNOWN: "Unknown error - check logs",
        }
        
        return suggestions.get(error.error_type, "Unknown recovery action")