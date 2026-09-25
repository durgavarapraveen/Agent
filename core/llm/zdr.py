"""Zero Data Retention (ZDR) enforcement for LLM calls.

Two sides of retention are controlled here:

1. Provider side — the Bedrock/Mantle gateway request carries
   ``data_retention: "none"`` so prompts/completions are not retained or shared
   by the provider (kept in-region, not used for training/logging).
2. Our side — the platform's own LLM I/O log stores prompt/response CONTENT in
   the database. Under ZDR that is itself retention, so content is dropped and
   only metadata (provider/model/tokens/cost/timing) is kept.

ZDR is ON by default (``LLM_ZDR_REQUIRED`` unset or truthy); set
``LLM_ZDR_REQUIRED=0`` to allow retention. Extra provider headers can be added
with ``LLM_ZDR_HEADERS`` (a JSON object) for gateways that gate ZDR by header.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on", "required", "enabled"}
_FALSE = {"0", "false", "no", "off", "disabled"}


def zdr_required() -> bool:
    v = os.getenv("LLM_ZDR_REQUIRED", "").strip().lower()
    if v in _FALSE:
        return False
    # Default ON: absence of the flag means enforce ZDR.
    return True


def data_retention_value() -> str:
    """Value for the gateway's ``data_retention`` request field. 'none' under
    ZDR; otherwise whatever the operator set explicitly (or '')."""
    if zdr_required():
        return "none"
    return os.getenv("AWS_BEDROCK_DATA_RETENTION", "").strip()


def zdr_headers() -> Dict[str, str]:
    """Optional extra request headers for gateways that gate ZDR by header."""
    if not zdr_required():
        return {}
    raw = os.getenv("LLM_ZDR_HEADERS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return {str(k): str(v) for k, v in (data or {}).items()}
    except Exception as e:
        logger.warning("[zdr] LLM_ZDR_HEADERS ignored (bad JSON): %s", e)
        return {}


def persist_content_allowed() -> bool:
    """False under ZDR — the platform must not store prompt/response content."""
    return not zdr_required()


def status() -> Dict[str, object]:
    return {
        "zdr_required": zdr_required(),
        "data_retention": data_retention_value(),
        "persist_content": persist_content_allowed(),
        "extra_headers": sorted(zdr_headers().keys()),
    }
