"""Attacker-critic two-LLM loop for custom probes.

Wraps `run_custom_probe` calls with a critique step:

  1. Attacker proposes probe → critic scores {viability 0-1, will_be_blocked_by,
     revised_payload}
  2. If viability < 0.5 or a WAF/rate-limit issue is spotted, use the revised
     payload.
  3. Execute.
  4. If response looks blocked (403/406/429/challenge page), one refinement
     pass: critic proposes a bypass tamper, retry.

Kept off by default to avoid slowing every probe — enable per-scan with the
env `ADVERSARIAL_CRITIC=1` or programmatically at high-value phases.
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def enabled() -> bool:
    return os.getenv("ADVERSARIAL_CRITIC", "0") in ("1", "true", "yes")


CRITIC_PROMPT = """You are an expert red-team critic. Given the attacker's proposed HTTP probe below, score it and, if needed, revise it.

Return ONE strict-JSON object:
{
  "viability": 0.0-1.0,        // likelihood this probe reaches its goal on the target
  "issues": ["<blocker>", ...], // e.g. WAF signature, missing auth, rate-limit likely
  "revised_payload": {          // only include if viability < 0.7
    "method": "...", "url": "...", "headers": {...}, "body": "..."
  },
  "reasoning": "<one sentence>"
}

TARGET CONTEXT:
- Target base: %TARGET%
- WAF detected: %WAF%
- Auth active: %AUTH%
- Tech stack: %TECH%

PROPOSED PROBE:
%PROBE_JSON%

HYPOTHESIS:
%HYPOTHESIS%
"""


BYPASS_PROMPT = """The probe returned a blocked-looking response. Suggest ONE concrete bypass and return a revised probe.

Return strict JSON: {"method","url","headers","body","tamper_used":"<short name>"}

BLOCKED RESPONSE (headers + first 800 bytes):
%RESP%

ORIGINAL PROBE:
%PROBE%
"""


def _blocked_looking(resp_text: str) -> bool:
    if not resp_text or not resp_text.startswith("HTTP"):
        return False
    first_line = resp_text.split("\n", 1)[0].lower()
    m = re.search(r"http\s+(\d{3})", first_line)
    if not m:
        return False
    status = int(m.group(1))
    if status in (403, 406, 429, 451, 503):
        return True
    body = resp_text.lower()
    for sig in ("access denied", "cloudflare", "attention required", "captcha",
                "your request has been blocked", "web application firewall",
                "not acceptable", "forbidden", "incapsula", "sucuri"):
        if sig in body:
            return True
    return False


async def _critic_llm(prompt: str) -> Optional[Dict]:
    try:
        from agents.llm_harness_adapter import get_llm
        from agents.universal_llm_harness import TaskTier
        llm = get_llm()
        if llm is None:
            return None
        resp = await asyncio.wait_for(
            llm.generate_response(
                prompt=prompt, max_tokens=800, temperature=0.2, tier=TaskTier.SMALL),
            timeout=60.0,
        )
        text = (getattr(resp, "content", "") or "").strip()
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        return json.loads(m.group(0))
    except asyncio.TimeoutError:
        logger.warning("[Critic] LLM call timed out after 60s")
        return None
    except Exception as e:
        logger.debug(f"[Critic] LLM call failed: {e}")
        return None


async def critique_and_run(probe_args: Dict, ctx, tracker=None) -> str:
    """Drop-in wrapper for run_custom_probe with critic pre/post-passes."""
    from core.exploitation.custom_probe import run_custom_probe
    if not enabled():
        return await run_custom_probe(probe_args, ctx, tracker)
    # Context for critic
    intel = getattr(ctx, "prior_intel", {}) or {}
    waf = intel.get("waf_detected") or ""
    techs = getattr(ctx, "technologies", {}) or {}
    tech_str = ", ".join({t for vs in techs.values() for t in (vs if isinstance(vs, list) else [vs]) if isinstance(t, str)})[:200]
    auth_active = "yes" if (getattr(ctx, "auth_headers", {}) or {}).get("Authorization") else "no"

    from core.llm.prompt_safety import fence_untrusted
    critique = await _critic_llm(CRITIC_PROMPT
        .replace("%TARGET%", str(ctx.target))
        .replace("%WAF%", waf or "none")
        .replace("%AUTH%", auth_active)
        .replace("%TECH%", tech_str or "unknown")
        .replace("%PROBE_JSON%", fence_untrusted(
            json.dumps({k: probe_args.get(k) for k in
                        ("method", "url", "headers", "body")}, default=str)[:2000],
            label="probe"))
        .replace("%HYPOTHESIS%", fence_untrusted(
            str(probe_args.get("hypothesis") or ""), label="hypothesis"))
    )
    if critique and float(critique.get("viability", 1.0)) < 0.5 and critique.get("revised_payload"):
        rev = critique["revised_payload"]
        logger.info(f"[Critic] Revised probe pre-execution (viability={critique.get('viability')}): "
                    f"{critique.get('reasoning','')[:120]}")
        for k in ("method", "url", "headers", "body"):
            if k in rev:
                probe_args[k] = rev[k]

    resp = await run_custom_probe(probe_args, ctx, tracker)
    if not _blocked_looking(resp):
        return resp

    # One bypass pass. Response body is attacker-controlled — fence it as
    # untrusted data so a crafted 500 page can't inject critic directives.
    from core.llm.prompt_safety import fence_untrusted
    _fenced_resp = fence_untrusted(resp[:1200], label="target_response")
    _fenced_probe = fence_untrusted(
        json.dumps({k: probe_args.get(k) for k in
                    ("method", "url", "headers", "body")}, default=str)[:1500],
        label="probe")
    bypass = await _critic_llm(BYPASS_PROMPT
        .replace("%RESP%", _fenced_resp)
        .replace("%PROBE%", _fenced_probe))
    if not bypass:
        return resp
    logger.info(f"[Critic] Retrying with bypass tamper={bypass.get('tamper_used','?')}")
    for k in ("method", "url", "headers", "body"):
        if k in bypass:
            probe_args[k] = bypass[k]
    return await run_custom_probe(probe_args, ctx, tracker)
