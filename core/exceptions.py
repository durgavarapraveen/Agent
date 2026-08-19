class SecurityAssessmentException(Exception):
    """Base exception for the security assessment platform."""
    pass

class AgentException(SecurityAssessmentException):
    """Agent-related errors."""
    pass

class TaskException(SecurityAssessmentException):
    """Task-related errors."""
    pass

class ScopeViolationException(SecurityAssessmentException):
    """Scope violation detected."""
    pass

class ToolExecutionException(SecurityAssessmentException):
    """Tool execution failed."""
    pass

class KnowledgeStoreException(SecurityAssessmentException):
    """Knowledge store operation failed."""
    pass

class LLMException(SecurityAssessmentException):
    """LLM provider error."""
    pass

class MCPException(SecurityAssessmentException):
    """MCP-related error."""
    pass

class ValidationException(SecurityAssessmentException):
    """Validation failed."""
    pass

class TimeoutException(SecurityAssessmentException):
    """Operation timed out."""
    pass
