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


def cached_available() -> Set[str]:
    """Already-discovered models, WITHOUT triggering a network call. Empty until
    something calls discover_available()."""
    return set(_discovered or set())


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


# ── CLI: `python -m core.llm.model_availability` ────────────────────────
def _print_report() -> int:
    """Print accessible models, the role→model mapping, pricing and ZDR status."""
    from core.llm.model_roles import (
        ModelRole, model_for_role, configured_model, role_source)
    from core.economics.pricing import price_for, is_known
    from core.llm.zdr import status as zdr_status

    print("\n=== Bedrock model availability ===")
    al = allowlist()
    print(f"Allowlist (AWS_BEDROCK_ALLOWED_MODELS): "
          f"{', '.join(sorted(al)) if al else '(none — all allowed)'}")

    # Force discovery for the CLI regardless of the opt-in flag (explicit action).
    reset_cache()
    try:
        available = discover_available(force=True)
    except Exception as e:
        available = set()
        print(f"Discovery error: {e}")
    if available:
        print(f"\nAccessible models ({len(available)}):")
        for m in sorted(available):
            allowed = (not al) or _matches(m, al)
            mark = "*" if allowed else "-"  # * = in allowlist / usable
            print(f"  {mark} {m}")
        if al:
            print("  (* = permitted by your allowlist; - = discovered but excluded)")
    else:
        print("\nNo models discovered (need Bedrock creds / gateway reachable, "
              "or set AWS_BEDROCK_ALLOWED_MODELS to pin them).")

    print("\n=== Role -> model routing ===")
    print(f"{'ROLE':<11} {'MODEL':<44} {'SRC':<12} {'ACCESS':<8} RATE $/1M (in/out)")
    downgrades = []
    for r in ModelRole:
        model = model_for_role(r)
        wanted = configured_model(r)
        downgraded = wanted != model
        if downgraded:
            src = "downgraded"
            downgrades.append((r.value, wanted, model))
        else:
            src = role_source(r)  # configured | auto | fallback
        acc = "yes" if is_allowed(model) else "BLOCKED"
        pin, pout = price_for(model)
        rate = f"{pin}/{pout}" if is_known(model) else "no price"
        print(f"{r.value:<11} {model[:44]:<44} {src:<12} {acc:<8} {rate}")
    if downgrades:
        print("\n  Downgraded (configured model not accessible -> swapped to an "
              "allowed fallback):")
        for role, wanted, got in downgrades:
            print(f"    {role}: wanted {wanted!r} -> using {got!r} "
                  f"(add {wanted!r} to AWS_BEDROCK_ALLOWED_MODELS to keep it)")

    z = zdr_status()
    print(f"\n=== ZDR ===\n  required={z['zdr_required']}  "
          f"data_retention={z['data_retention']!r}  "
          f"persist_content={z['persist_content']}")
    print()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_print_report())
