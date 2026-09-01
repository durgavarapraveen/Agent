import os
import logging
from enum import Enum

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

class ExecutionMode(Enum):
    DETERMINISTIC = "A"
    AGENTIC = "B"
    HYBRID = "A_B"

class ExecutionConfig:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ExecutionConfig, cls).__new__(cls)
            cls._instance._init_config()
        return cls._instance

    def _init_config(self):
        mode_str = os.getenv("EXECUTION_MODE", "A").upper()
        if mode_str == "A":
            self.mode = ExecutionMode.DETERMINISTIC
        elif mode_str == "B":
            self.mode = ExecutionMode.AGENTIC
        elif mode_str == "A_B":
            self.mode = ExecutionMode.HYBRID
        else:
            logger.warning(f"Invalid EXECUTION_MODE '{mode_str}', defaulting to 'A' (DETERMINISTIC)")
            self.mode = ExecutionMode.DETERMINISTIC

        self.deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
        self.deepseek_model = os.getenv("DEEPSEEK_MODEL")
        self.claude_api_key = os.getenv("CLAUDE_API_KEY")
        self.claude_model = os.getenv("CLAUDE_MODEL")
        
        self.enable_mcp_server = os.getenv("ENABLE_MCP_SERVER", "false").lower() == "true"
        self.mcp_server_port = os.getenv("MCP_SERVER_PORT")
        self.fallback_on_error = os.getenv("FALLBACK_ON_ERROR", "false").lower() == "true"

        self._validate()
        self._log_config()

    def _validate(self):
        if self.is_mode_a_enabled() and not self.deepseek_api_key:
            logger.warning("DEEPSEEK_API_KEY is not set but Mode A is enabled.")
        if self.is_mode_b_enabled() and not self.claude_api_key:
            logger.warning("CLAUDE_API_KEY is not set but Mode B is enabled.")

    def _log_config(self):
        logger.info(f"Execution Config Initialized: Mode={self.mode.name} ({self.mode.value})")

    def is_mode_a_enabled(self) -> bool:
        return self.mode in (ExecutionMode.DETERMINISTIC, ExecutionMode.HYBRID)

    def is_mode_b_enabled(self) -> bool:
        return self.mode in (ExecutionMode.AGENTIC, ExecutionMode.HYBRID)

    def should_use_mode_a_primary(self) -> bool:
        return self.mode in (ExecutionMode.DETERMINISTIC, ExecutionMode.HYBRID)

    def should_use_mode_b_primary(self) -> bool:
        return self.mode == ExecutionMode.AGENTIC

    def can_fallback_to_b(self) -> bool:
        return self.mode == ExecutionMode.HYBRID and self.fallback_on_error


def get_execution_config() -> ExecutionConfig:
    return ExecutionConfig()
