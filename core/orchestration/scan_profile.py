"""Scan selectivity profile — how exhaustively the specialist battery tests.

Two modes:

- ``lab``      → **exhaustive**: run every registered probe/family regardless of
                 plan relevance. Correct for authorized labs / CTFs (Juice Shop),
                 where maximum coverage matters more than noise/cost.
- ``standard`` → **selective** (default): only run a family when the engagement
                 plan marks it relevant OR a live surface signal indicates it
                 (e.g. a JWT present → CRYPTO, a chatbot endpoint → the LLM
                 probe). So a real target is not blasted with every technique —
                 no web3 probe on a non-web3 site — while advanced techniques
                 still auto-fire the moment their surface actually exists.

Precedence for the mode: explicit ``NEO_FULL_BATTERY`` wins (back-compatible:
1=lab, 0=standard), else ``NEO_SCAN_PROFILE`` (lab|standard), else ``standard``.
"""
from __future__ import annotations

import os
from typing import Any, Optional

# Narrow / optional families that should be gated out on a generic target unless
# a concrete surface signal says otherwise. Keyword → the ctx text that implies
# the family is worth running even when the plan didn't scope it in.
_SURFACE_SIGNALS = {
    "web3": ("web3", "ethereum", "metamask", "wallet", "solidity", "abi",
             "0x", "smart contract", "blockchain", "nft"),
    "graphql": ("graphql", "/graphql", "apollo", "__schema"),
    "websocket": ("websocket", "socket.io", "ws://", "wss://", "/ws"),
    # LLM / prompt-injection surface (chatbot / assistant endpoints).
    "injection_llm": ("chatbot", "/chat", "assistant", "llm", "openai",
                      "prompt", "support bot", "rest/chatbot"),
}


def profile() -> str:
    """Return the active scan profile: 'lab' or 'standard'."""
    fb = os.getenv("NEO_FULL_BATTERY")
    if fb is not None:                       # explicit override wins
        return "lab" if fb.strip() != "0" else "standard"
    p = (os.getenv("NEO_SCAN_PROFILE", "standard") or "standard").strip().lower()
    return "lab" if p == "lab" else "standard"


def is_exhaustive() -> bool:
    """True → run the full battery (every family), skipping plan relevance."""
    return profile() == "lab"


def _ctx_blob(ctx: Any) -> str:
    """Cheap lowercased text view of the target's discovered surface for
    keyword signal matching. Defensive: never raises."""
    parts = []
    try:
        for ep in (getattr(ctx, "endpoints", []) or [])[:400]:
            if isinstance(ep, str):
                parts.append(ep)
            elif isinstance(ep, dict):
                parts.append(str(ep.get("url", "")))
            else:
                parts.append(str(getattr(ep, "url", "")))
    except Exception:
        pass
    try:
        tech = getattr(ctx, "technologies", None)
        if isinstance(tech, dict):
            parts.extend(str(k) for k in tech.keys())
        elif tech:
            parts.append(str(tech))
    except Exception:
        pass
    try:
        for c in (getattr(ctx, "captured_requests", []) or [])[:400]:
            if isinstance(c, dict):
                parts.append(str(c.get("url", "")))
    except Exception:
        pass
    return " ".join(parts).lower()


def _has_jwt(ctx: Any) -> bool:
    """A JWT / signed token anywhere → crypto analysis is worthwhile."""
    try:
        blob = " ".join(str(v) for v in (getattr(ctx, "auth_headers", {}) or {}).values())
        if "eyj" in blob.lower():            # base64url '{"' JWT header prefix
            return True
        for c in (getattr(ctx, "captured_requests", []) or [])[:400]:
            h = (c.get("headers") if isinstance(c, dict) else {}) or {}
            if any("eyj" in str(v).lower() for v in h.values()):
                return True
    except Exception:
        pass
    return False


def surface_relevant(ctx: Any, family_value: str) -> Optional[bool]:
    """Whether a live surface signal indicates this family should run even in
    'standard' mode. Returns True (signal present), or None (no opinion — defer
    to the engagement plan). Never returns False so it can only *widen*, never
    override, the plan's own relevance decision."""
    fam = (family_value or "").lower()
    blob = _ctx_blob(ctx)
    if fam == "crypto":
        return True if (_has_jwt(ctx) or "jwt" in blob or "bearer" in blob) else None
    if fam == "web3":
        return True if any(k in blob for k in _SURFACE_SIGNALS["web3"]) else None
    # graphql / websocket / llm probes are inferred into broader families
    # (api/injection); expose their signals so those families are kept when the
    # specific surface exists.
    if fam in ("api", "injection"):
        for key in ("graphql", "websocket", "injection_llm"):
            if any(k in blob for k in _SURFACE_SIGNALS[key]):
                return True
    return None
