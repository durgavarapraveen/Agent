
class AutonomousPentestException(Exception):
    pass


class ToolValidationError(AutonomousPentestException):
    pass


class LLMEmptyResponseError(AutonomousPentestException):
    pass


class LLMInvalidJSONError(AutonomousPentestException):
    pass


class LLMSchemaValidationError(AutonomousPentestException):
    pass


class LLMProviderError(AutonomousPentestException):
    pass


class ToolNotFoundError(AutonomousPentestException):
    pass


class ToolInvalidArgumentError(AutonomousPentestException):
    pass


class ToolTimeoutError(AutonomousPentestException):
    pass


class ToolRuntimeError(AutonomousPentestException):
    pass


class AuthorizationError(AutonomousPentestException):
    pass


class TargetUnreachableError(AutonomousPentestException):
    pass


class DependencyFailureError(AutonomousPentestException):
    pass


class TaskTimeoutError(AutonomousPentestException):
    pass


class TaskCancelledError(AutonomousPentestException):
    pass


class NoProgressError(AutonomousPentestException):
    pass


# Compatibility Aliases
ScopeViolationException = AuthorizationError
ScopeViolationError = AuthorizationError
ToolException = ToolRuntimeError

