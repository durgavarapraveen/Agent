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

class ExecutionConfig:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ExecutionConfig, cls).__new__(cls)
            cls._instance._init_config()
        return cls._instance

    def _init_config(self):
        self.mode = ExecutionMode.DETERMINISTIC
        self.fallback_on_error = False
        self.bedrock_available = self._detect_bedrock()
        self._log_config()

    def _detect_bedrock(self) -> bool:
        """True only when Bedrock can plausibly be called: credentials (explicit
        keys OR a role/profile) AND a region. Fail-safe — when this is False,
        callers must treat the LLM layer as unavailable and stay deterministic
        rather than silently substituting heuristic output for real LLM output."""
        has_creds = bool(
            os.getenv("AWS_ACCESS_KEY_ID")
            or os.getenv("AWS_ROLE_ARN")
            or os.getenv("AWS_PROFILE")
            or os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
            or os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")  # ECS/task role
        )
        has_region = bool(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"))
        if not (has_creds and has_region):
            logger.warning("Bedrock unavailable (creds=%s, region=%s) — LLM layer "
                           "disabled; running deterministic paths only.",
                           has_creds, has_region)
            return False
        return True

    def is_bedrock_available(self) -> bool:
        return bool(getattr(self, "bedrock_available", False))

    def _log_config(self):
        logger.info("Execution Config: Mode=%s, Provider=bedrock, bedrock_available=%s",
                    self.mode.name, self.bedrock_available)

    def is_mode_a_enabled(self) -> bool:
        return True

    def is_mode_b_enabled(self) -> bool:
        return False

    def should_use_mode_a_primary(self) -> bool:
        return True

    def should_use_mode_b_primary(self) -> bool:
        return False

    def can_fallback_to_b(self) -> bool:
        return False


def get_execution_config() -> ExecutionConfig:
    return ExecutionConfig()
