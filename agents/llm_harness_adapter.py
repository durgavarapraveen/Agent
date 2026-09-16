import asyncio

from agents.universal_llm_harness import UniversalLLMHarness, ProviderType
from core.common.config import get_config

_harness = None
_harness_lock = asyncio.Lock()


async def initialize_llm():
    global _harness
    async with _harness_lock:
        if _harness is not None:
            return
        config = get_config()

        _harness = UniversalLLMHarness(
            primary_provider=ProviderType.BEDROCK,
            fallback_providers=[],
            max_budget_usd=float(config.get("LLM_MAX_BUDGET_USD", "100.0")),
            aws_bedrock_small_model=config.get(
                "AWS_BEDROCK_SMALL_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
            aws_bedrock_large_model=config.get(
                "AWS_BEDROCK_LARGE_MODEL", "us.anthropic.claude-sonnet-4-20250514-v1:0"),
            aws_region=config.get("AWS_REGION", "us-west-2"),
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
