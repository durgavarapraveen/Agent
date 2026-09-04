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

    @property
    def osint_enabled(self) -> bool:
        val = os.getenv('ENABLE_OSINT', os.getenv('OSINT_ENABLE', self.config.get('ENABLE_OSINT', 'true'))).lower()
        return val in ('true', 'yes', '1', 'on')

    @property
    def OSINT_ENABLED(self) -> bool:
        return self.osint_enabled

    @property
    def GITHUB_TOKEN(self) -> Optional[str]:
        return os.getenv('GITHUB_TOKEN', self.config.get('GITHUB_TOKEN'))

    @property
    def SHODAN_KEY(self) -> Optional[str]:
        return os.getenv('SHODAN_API_KEY', self.config.get('SHODAN_API_KEY'))

    @property
    def CENSYS_PAT(self) -> Optional[str]:
        legacy = os.getenv('CENSYS_UID') or os.getenv('CENSYS_SECRET') or os.getenv('CENSYS_API_ID') or os.getenv('CENSYS_API_SECRET') or self.config.get('CENSYS_UID') or self.config.get('CENSYS_SECRET')
        if legacy and not (os.getenv('CENSYS_PAT') or self.config.get('CENSYS_PAT')):
            logger.warning("CENSYS_UID / CENSYS_SECRET / CENSYS_API_ID / CENSYS_API_SECRET are deprecated. Please use CENSYS_PAT instead.")
        return os.getenv('CENSYS_PAT', os.getenv('CENSYS_TOKEN', self.config.get('CENSYS_PAT')))

    @property
    def CENSYS_UID(self) -> Optional[str]:
        logger.warning("CENSYS_UID is deprecated. Please use CENSYS_PAT instead.")
        return os.getenv('CENSYS_UID', self.config.get('CENSYS_UID'))

    @property
    def CENSYS_SECRET(self) -> Optional[str]:
        logger.warning("CENSYS_SECRET is deprecated. Please use CENSYS_PAT instead.")
        return os.getenv('CENSYS_SECRET', self.config.get('CENSYS_SECRET'))

    @property
    def ABUSEIPDB_KEY(self) -> Optional[str]:
        return os.getenv('ABUSEIPDB_API_KEY', self.config.get('ABUSEIPDB_API_KEY'))

    @property
    def VT_KEY(self) -> Optional[str]:
        return os.getenv('VIRUSTOTAL_API_KEY', self.config.get('VIRUSTOTAL_API_KEY'))

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

    @property
    def FREE_TIER_MODE(self) -> bool:
        return self.get_bool("FREE_TIER_MODE", True)

    @property
    def token_compression(self) -> bool:
        return self.get_bool("TOKEN_COMPRESSION", True)

    @token_compression.setter
    def token_compression(self, val: bool):
        self.config["TOKEN_COMPRESSION"] = str(val)

    @property
    def compression_threshold(self) -> int:
        return self.get_int("COMPRESSION_THRESHOLD", 500)

    @compression_threshold.setter
    def compression_threshold(self, val: int):
        self.config["COMPRESSION_THRESHOLD"] = str(val)

    @property
    def dedup_enabled(self) -> bool:
        return self.get_bool("DEDUP_ENABLED", True)

    @dedup_enabled.setter
    def dedup_enabled(self, val: bool):
        self.config["DEDUP_ENABLED"] = str(val)

    @property
    def significance_filter_enabled(self) -> bool:
        return self.get_bool("SIGNIFICANCE_FILTER_ENABLED", True)

    @significance_filter_enabled.setter
    def significance_filter_enabled(self, val: bool):
        self.config["SIGNIFICANCE_FILTER_ENABLED"] = str(val)

    @property
    def error_translation_enabled(self) -> bool:
        return self.get_bool("ERROR_TRANSLATION_ENABLED", True)

    @error_translation_enabled.setter
    def error_translation_enabled(self, val: bool):
        self.config["ERROR_TRANSLATION_ENABLED"] = str(val)

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
