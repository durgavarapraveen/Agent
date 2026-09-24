"""Task → model role routing over the Bedrock gateway (spec Phase 28/32/33).

The platform makes many LLM calls of very different difficulty. Sending every
one to the strongest model is slow and expensive; sending planning to a tiny
model is inaccurate. This module maps a task to a ROLE and each role to a
concrete Bedrock model id, so cheap work runs on a fast model and hard reasoning
runs on a strong one — better results and lower cost.

Roles and their env overrides (all optional; each falls back to the existing
small/large model so a 2-model deployment keeps working unchanged):

    FAST       AWS_BEDROCK_FAST_MODEL        classification, normalization, extraction
    REASONING  AWS_BEDROCK_REASONING_MODEL   vuln validation, cross-source correlation
    PLANNER    AWS_BEDROCK_PLANNER_MODEL     attack-path planning (strong reasoning)
    CODING     AWS_BEDROCK_CODING_MODEL      source/code analysis, exploit code
    VISION     AWS_BEDROCK_VISION_MODEL      screenshot/DOM image analysis
    EMBEDDING  AWS_BEDROCK_EMBEDDING_MODEL   vector embeddings

The rest of the system stays model-agnostic: callers ask for a role (or pass a
task name and let ``classify_task`` decide); this module resolves the id.
"""
from __future__ import annotations

import os
from enum import Enum
from typing import Optional, Tuple


class ModelRole(str, Enum):
    FAST = "fast"
    REASONING = "reasoning"
    PLANNER = "planner"
    CODING = "coding"
    VISION = "vision"
    EMBEDDING = "embedding"


# Role → env var holding an explicit model id.
_ROLE_ENV = {
    ModelRole.FAST: "AWS_BEDROCK_FAST_MODEL",
    ModelRole.REASONING: "AWS_BEDROCK_REASONING_MODEL",
    ModelRole.PLANNER: "AWS_BEDROCK_PLANNER_MODEL",
    ModelRole.CODING: "AWS_BEDROCK_CODING_MODEL",
    ModelRole.VISION: "AWS_BEDROCK_VISION_MODEL",
    ModelRole.EMBEDDING: "AWS_BEDROCK_EMBEDDING_MODEL",
}

# FAST maps to the SMALL tier; everything else to LARGE (for tier-based plumbing).
_FAST_ROLES = {ModelRole.FAST}


def role_tier(role: ModelRole):
    """Map a role to the legacy TaskTier so existing tier plumbing still works."""
    from core.common.schemas import TaskTier
    return TaskTier.SMALL if role in _FAST_ROLES else TaskTier.LARGE


def _small_large() -> Tuple[str, str]:
    try:
        from core.llm.bedrock_config import small_model, large_model
        return small_model(), large_model()
    except Exception:
        return "", ""


def model_for_role(role: ModelRole) -> str:
    """Resolve a role to a concrete model id: explicit env → sensible fallback.

    FAST falls back to the small model; every other role to the large model.
    VISION/EMBEDDING with no override fall back to large (which may not actually
    support that modality — callers should check ``has_role_model`` first).
    """
    env = _ROLE_ENV.get(role)
    if env:
        v = os.getenv(env, "").strip()
        if v:
            return v
    small, large = _small_large()
    return small if role in _FAST_ROLES else large


def has_role_model(role: ModelRole) -> bool:
    """True when the role has an EXPLICIT model configured (not just a fallback).
    Use for VISION/EMBEDDING before assuming the modality is available."""
    env = _ROLE_ENV.get(role)
    return bool(env and os.getenv(env, "").strip())


# ── task → role classification ──────────────────────────────────────────
_KEYWORDS = [
    (ModelRole.VISION, ("screenshot", "image", "vision", "ocr", "visual", "dom_image")),
    (ModelRole.EMBEDDING, ("embed", "embedding", "vector")),
    (ModelRole.CODING, ("code", "source", "sast", "ast", "exploit_code",
                        "payload_synth", "diff", "static_analysis")),
    (ModelRole.PLANNER, ("attack_path", "attack-path", "planning", "planner",
                         "strategy", "next_action", "action_select")),
    (ModelRole.REASONING, ("reason", "validate", "validation", "correlat",
                           "hypothesis", "exploit", "impact", "analysis", "judge")),
    (ModelRole.FAST, ("classif", "normaliz", "extract", "summary", "summariz",
                      "dedup", "rank", "label", "route", "triage", "tag", "parse")),
]


def classify_task(task_type: str) -> ModelRole:
    """Map a task-type string to a role. Unknown → REASONING (favor quality)."""
    t = (task_type or "").strip().lower()
    if not t:
        return ModelRole.REASONING
    for role, keys in _KEYWORDS:
        if any(k in t for k in keys):
            return role
    return ModelRole.REASONING


def resolve(task_or_role) -> dict:
    """One entry point: accept a ModelRole, a role name, or a task-type string;
    return {"role", "model", "tier"}."""
    if isinstance(task_or_role, ModelRole):
        role = task_or_role
    else:
        s = str(task_or_role or "").strip().lower()
        try:
            role = ModelRole(s)
        except ValueError:
            role = classify_task(s)
    return {"role": role, "model": model_for_role(role), "tier": role_tier(role)}
