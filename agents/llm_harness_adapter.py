# agents/llm_harness_adapter.py
from agents.universal_llm_harness import UniversalLLMHarness, ProviderType
from core.common.config import get_config

_harness = None

async def initialize_llm():
    global _harness
    config = get_config()
    
    _harness = UniversalLLMHarness(
        primary_provider=ProviderType.DEEPSEEK,
        fallback_providers=[ProviderType.GROQ, ProviderType.OLLAMA],
        max_budget_usd=float(config.get("LLM_MAX_BUDGET_USD", "100.0")),
        deepseek_api_key=config.get("DEEPSEEK_API_KEY"),
        deepseek_small_model=config.get("DEEPSEEK_SMALL_MODEL", "deepseek-v4-flash"),
        deepseek_large_model=config.get("DEEPSEEK_LARGE_MODEL", "deepseek-v4-pro"),
        deepseek_reasoning_effort=config.get("DEEPSEEK_REASONING_EFFORT", "high"),
        deepseek_user_id=config.get("DEEPSEEK_USER_ID"),
        groq_api_key=config.get("GROQ_API_KEY"),
        groq_small_model=config.get("GROQ_SMALL_MODEL", "mixtral-8x7b-32768"),
        groq_large_model=config.get("GROQ_LARGE_MODEL", "mixtral-8x7b-32768"),
    )
    await _harness.initialize()

def get_llm():
    return _harness

async def close_llm():
    if _harness:
        await _harness.close()
