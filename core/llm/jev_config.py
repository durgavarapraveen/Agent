"""Single source of truth for Jev (TypeSafe AI System-One) configuration.

Jev is NOT a text LLM — it returns typed, calibrated decisions (noul / choice /
score) with probabilities. It is used for fast, cheap classification/routing/
gating in the harness, complementing the reasoning LLM (Bedrock gateway).

Env contract:
    JEV_API_KEY        Bearer token (required to enable Jev)
    JEV_BASE_URL       API root (default https://api.typesafe.ai/v1)
    JEV_MODEL          model id (default jev-latest)
    NEO_JEV_ROUTING    "1" to let Jev recover a probe family from signals that
                       the cheap keyword matcher missed (opt-in; off by default)

Pricing: input $0.042 / 1M tokens, output free (no text generated).
"""
from __future__ import annotations

import os

DEFAULT_BASE_URL = "https://api.typesafe.ai/v1"
DEFAULT_MODEL = "jev-latest"

# input USD per 1M tokens (output is free — Jev emits typed decisions, not text)
PRICE_INPUT_PER_1M = 0.042


def jev_api_key() -> str:
    return (os.getenv("JEV_API_KEY") or "").strip()


def jev_base_url() -> str:
    return (os.getenv("JEV_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/")


def jev_model() -> str:
    return (os.getenv("JEV_MODEL") or DEFAULT_MODEL).strip()


def jev_enabled() -> bool:
    """Jev is usable at all (a key is configured)."""
    return bool(jev_api_key())


def jev_routing_enabled() -> bool:
    """Opt-in: use Jev to route otherwise-unmatched surface signals to a family."""
    return jev_enabled() and os.getenv("NEO_JEV_ROUTING", "0") == "1"


def jev_phase_gate_enabled() -> bool:
    """Opt-in: Jev score gates phase-progress (kills slow-stall loops)."""
    return jev_enabled() and os.getenv("NEO_JEV_PHASE_GATE", "0") == "1"


def jev_tool_gate_enabled() -> bool:
    """Opt-in: Jev noul risk-gate before a tool action fires (fail-open)."""
    return jev_enabled() and os.getenv("NEO_JEV_TOOL_GATE", "0") == "1"


def jev_triage_enabled() -> bool:
    """Opt-in: Jev corroborates confirmed findings (annotates, never suppresses)."""
    return jev_enabled() and os.getenv("NEO_JEV_TRIAGE", "0") == "1"


def jev_validate_enabled() -> bool:
    """Opt-in: Jev pre-screens findings so the expensive LLM validator can skip
    the ones Jev is highly confident are real. Only EXEMPTS from LLM review — it
    never marks a finding false-positive, so recall is preserved and cost drops."""
    return jev_enabled() and os.getenv("NEO_JEV_VALIDATE", "0") == "1"
