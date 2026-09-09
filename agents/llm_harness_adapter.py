# agents/llm_harness_adapter.py
import asyncio

from agents.universal_llm_harness import UniversalLLMHarness, ProviderType
from core.common.config import get_config

_harness = None
_harness_lock = asyncio.Lock()  # guards read-modify-write of _harness

# Model defaults for each provider.
_DEFAULT_DEEPSEEK_SMALL = "deepseek-chat"
_DEFAULT_DEEPSEEK_LARGE = "deepseek-reasoner"
_DEFAULT_GROQ_SMALL = "llama-3.1-8b-instant"
_DEFAULT_GROQ_LARGE = "llama-3.3-70b-versatile"
_DEFAULT_CLAUDE_CLI_SMALL = "claude-haiku-4-5-20251001"
_DEFAULT_CLAUDE_CLI_LARGE = "claude-sonnet-4-20250514"

# Map LLM_PROVIDER env var values to ProviderType
_PROVIDER_MAP = {
    "deepseek": ProviderType.DEEPSEEK,
    "claude_cli": ProviderType.CLAUDE_CLI,
    "groq": ProviderType.GROQ,
    "ollama": ProviderType.OLLAMA,
}


async def initialize_llm():
    global _harness
    async with _harness_lock:
        if _harness is not None:
            return
        config = get_config()

        provider_name = config.get("LLM_PROVIDER", "claude_cli").lower()
        primary = _PROVIDER_MAP.get(provider_name, ProviderType.CLAUDE_CLI)

        # Build fallback chain: DeepSeek if primary isn't it, then Groq, Ollama
        fallbacks = []
        if primary != ProviderType.DEEPSEEK:
            fallbacks.append(ProviderType.DEEPSEEK)
        if primary != ProviderType.GROQ:
            fallbacks.append(ProviderType.GROQ)
        if primary != ProviderType.OLLAMA:
            fallbacks.append(ProviderType.OLLAMA)

        _harness = UniversalLLMHarness(
            primary_provider=primary,
            fallback_providers=fallbacks,
            max_budget_usd=float(config.get("LLM_MAX_BUDGET_USD", "100.0")),
            # DeepSeek config (used if fallback or primary)
            deepseek_api_key=config.get("DEEPSEEK_API_KEY", ""),
            deepseek_small_model=config.get("DEEPSEEK_SMALL_MODEL", _DEFAULT_DEEPSEEK_SMALL),
            deepseek_large_model=config.get("DEEPSEEK_LARGE_MODEL", _DEFAULT_DEEPSEEK_LARGE),
            deepseek_reasoning_effort=config.get("DEEPSEEK_REASONING_EFFORT", "high"),
            deepseek_user_id=config.get("DEEPSEEK_USER_ID"),
            # Claude CLI config
            claude_cli_small_model=config.get("CLAUDE_CLI_SMALL_MODEL", _DEFAULT_CLAUDE_CLI_SMALL),
            claude_cli_large_model=config.get("CLAUDE_CLI_LARGE_MODEL", _DEFAULT_CLAUDE_CLI_LARGE),
            claude_binary=config.get("CLAUDE_BINARY", "claude"),
            # Groq config
            groq_api_key=config.get("GROQ_API_KEY", ""),
            groq_small_model=config.get("GROQ_SMALL_MODEL", _DEFAULT_GROQ_SMALL),
            groq_large_model=config.get("GROQ_LARGE_MODEL", _DEFAULT_GROQ_LARGE),
        )
        await _harness.initialize()

    # Initialize RAG pipeline (seeds cybersecurity knowledge on first run)
    try:
        from core.rag.pipeline import SecurityRAGPipeline
        rag = SecurityRAGPipeline(api_key=config.get("DEEPSEEK_API_KEY"))
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
