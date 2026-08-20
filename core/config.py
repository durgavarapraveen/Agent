"""
Config loader - reads from .env file
Simple, no external dependencies
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class Config:
    """Load config from .env file"""

    def __init__(self, env_file: str = ".env"):
        self.env_file = Path(env_file)
        self.config = {}
        self._load()

    def _load(self):
        """Load .env file"""
        if not self.env_file.exists():
            logger.warning(f".env file not found: {self.env_file}")
            return

        with open(self.env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    self.config[key.strip()] = value.strip()

        logger.info(f"Loaded config from {self.env_file}")

    def get(self, key: str, default: str = None) -> Optional[str]:
        """Get config value"""
        return self.config.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean config value"""
        val = self.config.get(key, str(default)).lower()
        return val in ('true', 'yes', '1', 'on')

    def get_int(self, key: str, default: int = 0) -> int:
        """Get integer config value"""
        try:
            return int(self.config.get(key, default))
        except ValueError:
            return default

    def __repr__(self):
        # Don't expose sensitive keys
        safe_keys = {k: v[:10] + "..." if len(v) > 10 else v 
                     for k, v in self.config.items() 
                     if "KEY" not in k and "SECRET" not in k}
        return f"Config({safe_keys})"


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global config instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config


def load_config(env_file: str = ".env") -> Config:
    """Load config from specific file"""
    global _config
    _config = Config(env_file)
    return _config