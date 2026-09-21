"""Single source of truth for the Bedrock LLM configuration.

The SAME LLM must run in dev and production — only the credential SOURCE differs
(env keys / `aws configure` locally → IAM role in AWS; boto3's default provider
chain resolves both automatically). To guarantee dev and prod cannot drift onto
different models or regions, every Bedrock call site reads its region + model ids
from here, with ONE default each.

Env contract (set identically in dev and prod):
    AWS_REGION                 e.g. us-east-1   (region where Bedrock model access is granted)
    AWS_BEDROCK_SMALL_MODEL    fast/cheap model id (hypothesis ranking, cheap calls)
    AWS_BEDROCK_LARGE_MODEL    capable model id  (payload generation, reasoning)

Credentials (NOT set in prod — IAM role supplies them):
    dev:  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY  (or `aws configure`, AWS_PROFILE)
    prod: instance/task IAM role (no keys in the environment)
"""
from __future__ import annotations

import os
from typing import Tuple

# One default per value — used ONLY when the env var is unset. Keeping a single
# default (not per-file defaults) is what prevents dev/prod divergence.
DEFAULT_REGION = "us-east-1"
DEFAULT_SMALL_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
DEFAULT_LARGE_MODEL = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# OpenAI-compatible Bedrock gateway (Bearer-token auth, /v1/chat/completions).
# When AWS_BEDROCK_BASE_URL + AWS_BEARER_TOKEN_BEDROCK are set, the provider hits
# this HTTP endpoint instead of boto3 invoke_model — no SigV4/IAM required.
DEFAULT_BASE_URL = ""


def bedrock_region() -> str:
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or DEFAULT_REGION


def bedrock_base_url() -> str:
    """Chat-completions URL for the OpenAI-compatible gateway ('' → use boto3)."""
    return os.getenv("AWS_BEDROCK_BASE_URL", DEFAULT_BASE_URL).strip()


def bedrock_api_token() -> str:
    """Bearer token for the gateway (AWS_BEARER_TOKEN_BEDROCK)."""
    return (os.getenv("AWS_BEARER_TOKEN_BEDROCK") or "").strip()


def small_model() -> str:
    return os.getenv("AWS_BEDROCK_SMALL_MODEL", DEFAULT_SMALL_MODEL)


def large_model() -> str:
    return os.getenv("AWS_BEDROCK_LARGE_MODEL", DEFAULT_LARGE_MODEL)


def bedrock_settings() -> Tuple[str, str, str]:
    """(region, small_model, large_model) — the whole LLM identity in one call."""
    return bedrock_region(), small_model(), large_model()
