# agents/llm_harness_adapter.py
from agents.universal_llm_harness import UniversalLLMHarness, TaskTier, ProviderType
from core.config import get_config
import asyncio

_harness = None

async def initialize_llm():
    global _harness
    config = get_config()
    
    _harness = UniversalLLMHarness(
        primary_provider=ProviderType.DEEPSEEK,
        fallback_providers=[ProviderType.GROQ, ProviderType.OLLAMA],
        max_budget_usd=float(config.get("LLM_MAX_BUDGET_USD", "100.0")),
        deepseek_api_key=config.get("DEEPSEEK_API_KEY"),
        groq_api_key=config.get("GROQ_API_KEY"),
    )
    await _harness.initialize()

def get_llm():
    return _harness

async def close_llm():
    if _harness:
        await _harness.close()