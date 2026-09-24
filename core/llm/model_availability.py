"""Which Bedrock models are actually usable, and routing gated to them.

An operator can only call the models their account/gateway grants. Routing must
never send a task to a model that will 400. This module answers "is this model
allowed?" from two sources:

1. An explicit allowlist — ``AWS_BEDROCK_ALLOWED_MODELS`` (comma-separated model
   ids or substrings). When set, ONLY these may be used.
2. Best-effort live discovery — the gateway's ``/models`` (OpenAI-compatible) or
   boto3 ``list_foundation_models``. Cached; failures degrade to "unknown"
   (which does not block, so a discovery outage never halts scanning).

``is_allowed`` is the gate: allowlist membership wins; else discovered membership
if discovery succeeded; else True (unknown → allow). ``enforce`` swaps a
disallowed model for the first allowed fallback so a role always resolves to a
usable model.
"""
from __future__ import annotations

import logging
import os
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

_discovered: Optional[Set[str]] = None


def allowlist() -> Set[str]:
    raw = os.getenv("AWS_BEDROCK_ALLOWED_MODELS", "")
    return {m.strip().lower() for m in raw.split(",") if m.strip()}


def _discovery_enabled() -> bool:
    # Live discovery is a network call — opt-in only, so unit paths and offline
    # runs never touch AWS. Enforcement otherwise relies on the explicit
    # allowlist (AWS_BEDROCK_ALLOWED_MODELS).
    return os.getenv("AWS_BEDROCK_DISCOVER_MODELS", "").strip().lower() in {
        "1", "true", "yes", "on"}


def _matches(model: str, pool: Set[str]) -> bool:
    m = (model or "").lower()
    return any(p == m or p in m or m in p for p in pool)


def discover_available(force: bool = False) -> Set[str]:
    """Best-effort set of usable model ids. Cached; empty means 'unknown'."""
    global _discovered
    if _discovered is not None and not force:
        return _discovered
    found: Set[str] = set()
    # 1) OpenAI-compatible gateway /models
    try:
        from core.llm.bedrock_config import bedrock_base_url
        base = bedrock_base_url()
        if base:
            from agents.providers.bedrock_provider import BedrockProvider
            prov = BedrockProvider()
            import asyncio
            from openai import OpenAI  # sync client for a one-shot list
            client = OpenAI(base_url=prov._sdk_base_url(), api_key=prov._mint_token(),
                            timeout=15.0, max_retries=1)
            for m in client.models.list().data:
                if getattr(m, "id", ""):
                    found.add(str(m.id).lower())
            del asyncio  # not needed; sync path
    except Exception as e:
        logger.debug("[availability] gateway /models discovery skipped: %s", e)
    # 2) boto3 list_foundation_models (direct Bedrock)
    if not found:
        try:
            import boto3
            from core.llm.bedrock_config import bedrock_region
            bc = boto3.client("bedrock", region_name=bedrock_region())
            for m in bc.list_foundation_models().get("modelSummaries", []):
                mid = m.get("modelId")
                if mid:
                    found.add(str(mid).lower())
        except Exception as e:
            logger.debug("[availability] boto3 discovery skipped: %s", e)
    _discovered = found
    if found:
        logger.info("[availability] discovered %d usable models", len(found))
    return found


def reset_cache() -> None:
    global _discovered
    _discovered = None


def is_allowed(model: str) -> bool:
    if not model:
        return False
    al = allowlist()
    if al:
        return _matches(model, al)
    if _discovery_enabled():
        disc = discover_available()
        if disc:
            return _matches(model, disc)
    return True  # no allowlist / discovery off → do not block


def enforce(model: str, fallbacks: Optional[List[str]] = None) -> str:
    """Return ``model`` if allowed, else the first allowed fallback, else the
    original model (with a warning) so callers still get a value."""
    if is_allowed(model):
        return model
    for fb in fallbacks or []:
        if fb and is_allowed(fb):
            logger.warning("[availability] %r not accessible; using fallback %r",
                           model, fb)
            return fb
    # Nothing allowed matched — try any allowlisted (or discovered) model.
    pool = allowlist() or (discover_available() if _discovery_enabled() else set())
    if pool:
        pick = sorted(pool)[0]
        logger.warning("[availability] %r not accessible; using %r", model, pick)
        return pick
    logger.warning("[availability] %r may not be accessible and no allowlist is "
                   "configured; using it as-is", model)
    return model
