"""
Custom exceptions for structured failure classification.
"""

class AutonomousPentestException(Exception):
    """Base exception for all autonomous pentest errors"""
    pass


class ToolValidationError(AutonomousPentestException):
    """Validation failure before tool execution"""
    pass


class LLMEmptyResponseError(AutonomousPentestException):
    """LLM returned an empty response"""
    pass


class LLMInvalidJSONError(AutonomousPentestException):
    """LLM returned invalid/unparseable JSON"""
    pass


class LLMSchemaValidationError(AutonomousPentestException):
    """LLM response failed schema validation"""
    pass


class LLMProviderError(AutonomousPentestException):
    """Error from LLM API provider"""
    pass


class ToolNotFoundError(AutonomousPentestException):
    """Tool is not installed or available"""
    pass


class ToolInvalidArgumentError(AutonomousPentestException):
    """Tool arguments or parameters are invalid"""
    pass


class ToolTimeoutError(AutonomousPentestException):
    """Tool execution timed out"""
    pass


class ToolRuntimeError(AutonomousPentestException):
    """Tool failed with a runtime error"""
    pass


class AuthorizationError(AutonomousPentestException):
    """Target scope authorization violation"""
    pass


class TargetUnreachableError(AutonomousPentestException):
    """Target host is unreachable"""
    pass


class DependencyFailureError(AutonomousPentestException):
    """Task dependency failed or blocked"""
    pass


class TaskTimeoutError(AutonomousPentestException):
    """Overall task execution timed out"""
    pass


class TaskCancelledError(AutonomousPentestException):
    """Task execution was cancelled"""
    pass


class NoProgressError(AutonomousPentestException):
    """No progress detected in execution loop"""
    pass


# Compatibility Aliases
ScopeViolationException = AuthorizationError
ScopeViolationError = AuthorizationError
ToolException = ToolRuntimeError

