
from __future__ import annotations

import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

_HYDE_SYSTEM = (
    "You are a cybersecurity expert. Given a user question or instruction, "
    "write a short (120-200 word) hypothetical passage that WOULD appear in "
    "an authoritative security reference (CWE entry, exploit writeup, tool "
    "manual, RFC, or vendor advisory) and that would answer the question. "
    "Include concrete technical details: payloads, function names, HTTP "
    "verbs, headers, CVE IDs, tool flags. Do NOT hedge, disclaim, or ask "
    "for clarification — write the passage as if it were a real reference "
    "excerpt. Return ONLY the passage, no preamble."
)


def _enabled() -> bool:
    v = os.getenv("RAG_HYDE_ENABLED", "1").strip().lower()
    return v not in ("0", "false", "no", "off", "")


async def transform_query(query: str, max_chars: int = 1200) -> str:
    if not _enabled() or not query or len(query) > 800:
        return query

    text = await _generate_hypothetical(query)
    if not text:
        return query
    # Concatenate original query + hypothetical doc. The original keeps
    # exact-term matches; the hypothetical adds semantic gravity.
    combined = f"{query}\n\n{text}"
    return combined[:max_chars]


async def _generate_hypothetical(query: str) -> Optional[str]:
    # Try the project's LLM harness first (already configured with keys / retry).
    try:
        from agents.universal_llm_harness import LLMHarness
        harness = LLMHarness()
        resp = await harness.complete(
            system=_HYDE_SYSTEM,
            user=query,
            temperature=0.2,
            max_tokens=280,
            task_tier="SMALL",
        )
        if resp and isinstance(resp, str):
            return _clean(resp)
        if isinstance(resp, dict):
            for key in ("content", "text", "output"):
                if resp.get(key):
                    return _clean(str(resp[key]))
    except Exception as e:
        logger.debug(f"[HyDE] harness path failed: {e}")

    # Fallback: use the adapter harness directly.
    try:
        from agents.llm_harness_adapter import get_llm, initialize_llm
        harness = get_llm()
        if not harness:
            await initialize_llm()
            harness = get_llm()
        if harness:
            text = await harness.generate_text(
                query, system=_HYDE_SYSTEM, max_tokens=280)
            if text:
                return _clean(text)
    except Exception as e:
        logger.debug(f"[HyDE] adapter fallback failed: {e}")

    return None


def _clean(text: str) -> str:
    t = re.sub(r"^```[a-z]*\n?", "", text.strip())
    t = re.sub(r"\n?```$", "", t).strip()
    return t
