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
        self._validate()
        self._log_config()

    def _validate(self):
        if not os.getenv("AWS_ACCESS_KEY_ID"):
            logger.warning("AWS credentials not set.")

    def _log_config(self):
        logger.info(f"Execution Config: Mode={self.mode.name}, Provider=bedrock")

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
