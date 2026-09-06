# agents/llm_harness_adapter.py
import asyncio

from agents.universal_llm_harness import UniversalLLMHarness, ProviderType
from core.common.config import get_config

_harness = None
_harness_lock = asyncio.Lock()  # guards read-modify-write of _harness

# Model defaults for each provider. Chosen to be currently-available models —
# the previous defaults (`mixtral-8x7b-32768`, `deepseek-v4-*`) were retired /
# never released, which silently disabled fallback and used non-reasoning
# planners for LARGE-tier tasks.
_DEFAULT_DEEPSEEK_SMALL = "deepseek-chat"      # cheaper conversation model
_DEFAULT_DEEPSEEK_LARGE = "deepseek-reasoner"  # reasoning-tuned; needed for planning
_DEFAULT_GROQ_SMALL = "llama-3.1-8b-instant"
_DEFAULT_GROQ_LARGE = "llama-3.3-70b-versatile"


async def initialize_llm():
    global _harness
    async with _harness_lock:
        if _harness is not None:
            return
        config = get_config()

        _harness = UniversalLLMHarness(
            primary_provider=ProviderType.DEEPSEEK,
            fallback_providers=[ProviderType.GROQ, ProviderType.OLLAMA],
            max_budget_usd=float(config.get("LLM_MAX_BUDGET_USD", "100.0")),
            deepseek_api_key=config.get("DEEPSEEK_API_KEY"),
            deepseek_small_model=config.get("DEEPSEEK_SMALL_MODEL", _DEFAULT_DEEPSEEK_SMALL),
            deepseek_large_model=config.get("DEEPSEEK_LARGE_MODEL", _DEFAULT_DEEPSEEK_LARGE),
            deepseek_reasoning_effort=config.get("DEEPSEEK_REASONING_EFFORT", "high"),
            deepseek_user_id=config.get("DEEPSEEK_USER_ID"),
            groq_api_key=config.get("GROQ_API_KEY"),
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
