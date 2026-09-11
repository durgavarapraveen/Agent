"""Phase 8.7 — prompt compression & system-prompt caching.

The brain/system prompt is resent on every decision call. Two levers:

  * providers that support prompt caching (Anthropic, OpenAI, Bedrock-Claude)
    can cache the large static system prompt so it is charged at a reduced rate
    after the first call — :func:`cache_control_for` emits the marker;
  * executor prompts are compressed to only the fields relevant to the current
    test instead of the full executor description.

Pure helpers — testable with no model. Complements ``token_optimizer`` (which
compresses *context*, not the system prompt / templates).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_CACHING_PROVIDERS = {"anthropic", "openai", "bedrock", "azure"}
# Cache the system prompt only when it's large enough to be worth it (Anthropic
# requires a minimum cacheable size in practice).
MIN_CACHEABLE_CHARS = 2000


def measure_prompt(text: str) -> Dict[str, int]:
    text = text or ""
    return {"chars": len(text), "est_tokens": max(1, len(text) // 4),
            "lines": text.count("\n") + 1 if text else 0}


def supports_prompt_caching(provider: str) -> bool:
    return (provider or "").lower() in _CACHING_PROVIDERS


def cache_control_for(provider: str, system_prompt: str) -> Optional[Dict[str, Any]]:
    """Return a provider-appropriate cache-control marker for a system prompt,
    or None when caching won't help (unsupported provider or too small)."""
    if not supports_prompt_caching(provider):
        return None
    if len(system_prompt or "") < MIN_CACHEABLE_CHARS:
        return None
    prov = provider.lower()
    if prov in ("anthropic", "bedrock"):
        # Anthropic-style: attach cache_control to the system block.
        return {"type": "ephemeral"}
    return {"cache": True}  # OpenAI/Azure automatic prompt caching hint


def compress_executor_prompt(template: str, relevant_fields: Dict[str, Any],
                             max_field_len: int = 500) -> str:
    """Render only the relevant fields into a compact prompt instead of a full
    executor description. Deterministic and small."""
    lines = [template.strip()] if template else []
    for k, v in relevant_fields.items():
        if v in (None, "", [], {}):
            continue
        val = str(v)
        if len(val) > max_field_len:
            val = val[:max_field_len] + "…"
        lines.append(f"{k}: {val}")
    return "\n".join(lines)


def strip_redundant_whitespace(prompt: str) -> str:
    """Collapse runs of blank lines and trailing spaces — cheap token savings."""
    s = re.sub(r"[ \t]+\n", "\n", prompt or "")
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


class PromptCompressor:

    def __init__(self, provider: str = ""):
        self.provider = provider

    def system_block(self, system_prompt: str) -> Dict[str, Any]:
        """Build a system block with cache-control when supported."""
        block: Dict[str, Any] = {"text": system_prompt}
        cc = cache_control_for(self.provider, system_prompt)
        if cc:
            block["cache_control"] = cc
        return block

    def estimate_savings(self, system_prompt: str, calls: int) -> Dict[str, Any]:
        """Rough input-token savings from caching a system prompt across calls."""
        tokens = measure_prompt(system_prompt)["est_tokens"]
        cacheable = supports_prompt_caching(self.provider) and len(system_prompt) >= MIN_CACHEABLE_CHARS
        # Cached reads are ~10% the cost of a fresh read on Anthropic.
        saved = int(tokens * (calls - 1) * 0.9) if (cacheable and calls > 1) else 0
        return {"system_tokens": tokens, "calls": calls, "cacheable": cacheable,
                "est_tokens_saved": saved}
