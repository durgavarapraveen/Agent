import asyncio
import os
from pathlib import Path

from agents.universal_llm_harness import UniversalLLMHarness, ProviderType
from core.common.config import get_config

_harness = None
_harness_lock = asyncio.Lock()

# UI-managed LLM provider choice (Settings page). Persisted to a file so scan
# subprocesses pick it up, and mirrored into os.environ so ones spawned now
# inherit it. Precedence: env → this file → .env config → default.
_PROVIDER_FILE = Path(".antigravity") / "llm_provider"
_VALID_PROVIDERS = ("claude_cli", "bedrock", "deepseek")

# UI-managed DeepSeek API key. Same pattern as the provider file so a scan
# subprocess picks it up. Precedence: env → this file → .env config.
_DEEPSEEK_KEY_FILE = Path(".antigravity") / "deepseek_api_key"


def _deepseek_api_key(config=None) -> str:
    v = (os.getenv("DEEPSEEK_API_KEY") or "").strip()
    if v:
        return v
    try:
        fv = _DEEPSEEK_KEY_FILE.read_text(encoding="utf-8").strip()
        if fv:
            return fv
    except Exception:
        pass
    cfg = config if config is not None else get_config()
    return (cfg.get("DEEPSEEK_API_KEY", "") or "").strip()


def set_deepseek_api_key(key: str) -> bool:
    """Persist the UI DeepSeek key; takes effect on the next scan."""
    k = (key or "").strip()
    _DEEPSEEK_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not k:
        try:
            _DEEPSEEK_KEY_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        os.environ.pop("DEEPSEEK_API_KEY", None)
        return True
    _DEEPSEEK_KEY_FILE.write_text(k, encoding="utf-8")
    try:
        os.chmod(_DEEPSEEK_KEY_FILE, 0o600)  # restrict — it's a secret
    except Exception:
        pass
    os.environ["DEEPSEEK_API_KEY"] = k       # spawned subprocesses inherit it
    return True


def has_deepseek_api_key() -> bool:
    return bool(_deepseek_api_key())


def get_provider() -> str:
    """Resolve the active LLM provider (env → UI file → .env → default)."""
    v = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    if v in _VALID_PROVIDERS:
        return v
    try:
        fv = _PROVIDER_FILE.read_text(encoding="utf-8").strip().lower()
        if fv in _VALID_PROVIDERS:
            return fv
    except Exception:
        pass
    cv = (get_config().get("LLM_PROVIDER", "") or "").strip().lower()
    return cv if cv in _VALID_PROVIDERS else "claude_cli"


def set_provider(provider: str) -> str:
    """Persist the UI provider choice; takes effect on the next scan."""
    p = (provider or "").strip().lower()
    if p not in _VALID_PROVIDERS:
        raise ValueError(f"provider must be one of {_VALID_PROVIDERS}")
    _PROVIDER_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PROVIDER_FILE.write_text(p, encoding="utf-8")
    os.environ["LLM_PROVIDER"] = p   # spawned scan subprocesses inherit this
    return p


async def initialize_llm():
    global _harness
    async with _harness_lock:
        if _harness is not None:
            return
        config = get_config()
        budget = float(config.get("LLM_MAX_BUDGET_USD", "100.0"))

        # Provider selection (env → UI Settings file → .env → default claude_cli).
        provider = get_provider()

        if provider == "bedrock":
            # Single source of truth so dev and prod use the IDENTICAL LLM
            # (only credentials differ: env keys in dev, IAM role in prod).
            from core.llm.bedrock_config import bedrock_settings
            region, small, large = bedrock_settings()
            _harness = UniversalLLMHarness(
                primary_provider=ProviderType.BEDROCK,
                fallback_providers=[],
                max_budget_usd=budget,
                aws_bedrock_small_model=small,
                aws_bedrock_large_model=large,
                aws_region=region,
            )
        elif provider == "deepseek":
            # DeepSeek API (OpenAI-compatible). Key + models from env/config.
            _harness = UniversalLLMHarness(
                primary_provider=ProviderType.DEEPSEEK,
                fallback_providers=[],
                max_budget_usd=budget,
                deepseek_small_model=os.getenv("DEEPSEEK_SMALL_MODEL", "deepseek-chat"),
                deepseek_large_model=os.getenv("DEEPSEEK_LARGE_MODEL", "deepseek-chat"),
                deepseek_api_key=_deepseek_api_key(config),
                deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", config.get("DEEPSEEK_BASE_URL", "")),
            )
        else:
            # Claude CLI — same model family (haiku=small, sonnet=large).
            _harness = UniversalLLMHarness(
                primary_provider=ProviderType.CLAUDE_CLI,
                fallback_providers=[],
                max_budget_usd=budget,
                cli_small_model=os.getenv("CLAUDE_CLI_SMALL_MODEL", "haiku"),
                cli_large_model=os.getenv("CLAUDE_CLI_LARGE_MODEL", "sonnet"),
            )
        await _harness.initialize()

    try:
        from core.rag.pipeline import SecurityRAGPipeline
        rag = SecurityRAGPipeline()
        await rag.initialize()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"RAG pipeline init skipped (non-fatal): {e}")

def get_llm():
    return _harness

async def close_llm():
    global _harness
    async with _harness_lock:
        if _harness:
            try:
                await _harness.close()
            finally:
                _harness = None
