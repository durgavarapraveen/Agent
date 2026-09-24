"""Authoritative per-model LLM pricing (spec Phase 29).

Cost must be computed from a real, per-model rate — never a fabricated default.
Rates are USD per 1,000,000 tokens as (input, output). The registry below holds
published defaults; operators override with their actual Bedrock/gateway rates
via env so accounting matches the invoice:

    LLM_PRICING_JSON = {"deepseek-v3.2": [0.27, 1.10], "my-model": [0.5, 1.5]}

Lookup is by longest matching substring of the model id (so "deepseek-v3.2"
wins over "deepseek"). An UNKNOWN model returns (0.0, 0.0) and logs a warning
once — the cost then reads as an explicit 0 (not a made-up number), and
``is_known(model)`` is False so callers/UI can flag it. Register the model or
set LLM_PRICING_JSON to fix it.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# (input_usd_per_1M, output_usd_per_1M). Keys are matched as substrings of the
# lowercased model id; keep more-specific keys longer than generic ones.
_DEFAULT_PRICING: Dict[str, Tuple[float, float]] = {
    # Anthropic Claude (Bedrock)
    "haiku": (0.80, 4.00),
    "claude-3-5-haiku": (0.80, 4.00),
    "sonnet": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "opus": (15.00, 75.00),
    # DeepSeek (Bedrock Mantle gateway)
    "deepseek": (0.27, 1.10),
    "deepseek-v3": (0.27, 1.10),
    "deepseek-v3.1": (0.27, 1.10),
    "deepseek-v3.2": (0.27, 0.42),
    "deepseek-r1": (0.55, 2.19),
    # Other gateway models (best-effort public estimates — override exact
    # contract rates with LLM_PRICING_JSON). Kept distinct per family/size.
    "qwen": (0.20, 0.60),
    "qwen3-32b": (0.15, 0.60),
    "qwen3-coder": (0.30, 1.20),
    "qwen3-vl": (0.30, 0.90),
    "qwen3-next": (0.25, 1.00),
    "gpt-oss": (0.15, 0.60),
    "glm": (0.30, 1.10),
    "glm-4.7": (0.30, 1.10),
    "glm-5": (0.60, 2.20),
    "llama": (0.20, 0.60),
    "llama4": (0.25, 0.85),
    "mistral-large": (2.00, 6.00),
    "mistral-small": (0.20, 0.60),
    "ministral": (0.10, 0.30),
    "kimi": (0.55, 2.20),
    "minimax": (0.30, 1.10),
    "grok": (3.00, 15.00),
    "nemotron": (0.20, 0.80),
    # Amazon Nova / Titan (Bedrock)
    "nova-micro": (0.035, 0.14),
    "nova-lite": (0.06, 0.24),
    "nova-pro": (0.80, 3.20),
    "titan-embed": (0.02, 0.0),
    "cohere.embed": (0.10, 0.0),
}

_warned: set = set()
_overrides_cache: Optional[Dict[str, Tuple[float, float]]] = None


def _load_overrides() -> Dict[str, Tuple[float, float]]:
    global _overrides_cache
    if _overrides_cache is not None:
        return _overrides_cache
    out: Dict[str, Tuple[float, float]] = {}
    raw = os.getenv("LLM_PRICING_JSON", "").strip()
    if raw:
        try:
            data = json.loads(raw)
            for k, v in (data or {}).items():
                if isinstance(v, (list, tuple)) and len(v) == 2:
                    out[str(k).lower()] = (float(v[0]), float(v[1]))
        except Exception as e:
            logger.warning("[pricing] LLM_PRICING_JSON ignored (bad JSON): %s", e)
    _overrides_cache = out
    return out


def reset_cache() -> None:
    """Clear cached env overrides (for tests / after config change)."""
    global _overrides_cache
    _overrides_cache = None
    _warned.clear()


def _match(model: str) -> Optional[Tuple[float, float]]:
    m = (model or "").lower()
    if not m:
        return None
    table = dict(_DEFAULT_PRICING)
    table.update(_load_overrides())  # overrides win
    # Longest matching key wins (most specific).
    best_key = None
    for key in table:
        if key in m and (best_key is None or len(key) > len(best_key)):
            best_key = key
    return table[best_key] if best_key else None


def is_known(model: str) -> bool:
    return _match(model) is not None


def price_for(model: str) -> Tuple[float, float]:
    """(input, output) USD per 1M tokens. Unknown → (0.0, 0.0) + warn once."""
    hit = _match(model)
    if hit is not None:
        return hit
    key = (model or "").lower()
    if key not in _warned:
        _warned.add(key)
        logger.warning("[pricing] no rate for model %r — cost recorded as 0. "
                       "Set LLM_PRICING_JSON to add it.", model)
    return (0.0, 0.0)


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    """Exact cost from the per-model rate. 0.0 for an unknown model (not guessed)."""
    pin, pout = price_for(model)
    return (int(input_tokens) * pin + int(output_tokens) * pout) / 1_000_000
