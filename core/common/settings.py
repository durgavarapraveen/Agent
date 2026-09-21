"""Typed settings facade — the single, canonical place to read configuration.

Precedence (highest first): process env var → .env file (via core.common.config)
→ the default passed here. This mirrors, in ONE place, the `os.getenv(X, config.get(X, d))`
pattern that was previously copy-pasted across the codebase (and drifted).

New code should read config through `settings` instead of calling `os.getenv`
directly, so the config surface is discoverable and typed. Legacy call sites keep
working unchanged.

    from core.common.settings import settings
    settings.llm_provider            # "claude_cli" | "bedrock" | "deepseek"
    settings.greybox_dynamic_timeout # int seconds
"""
from __future__ import annotations

import os
from typing import List, Optional

from core.common.config import get_config


def _raw(key: str, default: str = "") -> str:
    v = os.getenv(key)
    if v is not None and v != "":
        return v
    try:
        cv = get_config().get(key, None)
    except Exception:
        cv = None
    return cv if cv not in (None, "") else default


class Settings:
    """Read-only typed view over env + .env. Values are resolved live on access
    so a change (e.g. UI writing an env var) is picked up without a restart."""

    # ── helpers ──
    def str(self, key: str, default: str = "") -> str:
        return _raw(key, default)

    def int(self, key: str, default: int = 0) -> int:
        try:
            return int(_raw(key, str(default)))
        except (ValueError, TypeError):
            return default

    def float(self, key: str, default: float = 0.0) -> float:
        try:
            return float(_raw(key, str(default)))
        except (ValueError, TypeError):
            return default

    def bool(self, key: str, default: bool = False) -> bool:
        return _raw(key, str(default)).strip().lower() in ("1", "true", "yes", "on")

    def list(self, key: str, default: Optional[List[str]] = None) -> List[str]:
        raw = _raw(key, "")
        if not raw:
            return list(default or [])
        return [x for x in raw.replace(",", " ").split() if x]

    # ── LLM ──
    @property
    def llm_provider(self) -> str:
        # Delegates to the adapter's file+env precedence (UI Settings page).
        try:
            from agents.llm_harness_adapter import get_provider
            return get_provider()
        except Exception:
            return _raw("LLM_PROVIDER", "claude_cli")

    @property
    def llm_max_budget_usd(self) -> float:
        return self.float("LLM_MAX_BUDGET_USD", 100.0)

    @property
    def deepseek_api_key(self) -> str:
        try:
            from agents.llm_harness_adapter import _deepseek_api_key
            return _deepseek_api_key()
        except Exception:
            return _raw("DEEPSEEK_API_KEY")

    @property
    def deepseek_base_url(self) -> str:
        return _raw("DEEPSEEK_BASE_URL")

    @property
    def aws_region(self) -> str:
        return _raw("AWS_REGION", "us-east-1")

    # ── Database ──
    @property
    def database_url(self) -> str:
        return _raw("DATABASE_URL")

    @property
    def postgres_host(self) -> str:
        return _raw("POSTGRES_HOST", "localhost")

    # ── API server ──
    @property
    def api_host(self) -> str:
        return _raw("API_HOST", "0.0.0.0")

    @property
    def api_port(self) -> int:
        return self.int("API_PORT", 8000)

    @property
    def api_key(self) -> str:
        return _raw("API_KEY")

    @property
    def cors_origins(self) -> List[str]:
        return self.list("CORS_ORIGINS")

    # ── OOB / collaborator ──
    @property
    def oob_domain(self) -> str:
        return _raw("OOB_DOMAIN").rstrip("/")

    # ── SAST / grey-box ──
    @property
    def semgrep_rulesets(self) -> List[str]:
        return self.list("SEMGREP_RULESETS")

    @property
    def greybox_dynamic_timeout(self) -> int:
        return self.int("GREYBOX_DYNAMIC_TIMEOUT", 600)


# Canonical singleton.
settings = Settings()
