"""Human-in-the-loop (HITL) assist — generic bridge for tasks an automated
scanner cannot solve alone: client-side puzzles, steganography, OSINT lookups,
multi-step business logic, CAPTCHAs, or any "needs a human" decision.

Model (non-blocking by default, so autonomy is preserved):
  * a probe/agent calls ``request(...)`` → a pending row lands in
    ``human_requests`` and a note is posted to the shared blackboard + UI.
  * a human answers via the API/UI (``answer(...)``).
  * ``ask(...)`` is the optional BLOCKING variant for a value the probe needs
    inline (e.g. a CAPTCHA solution) — it waits up to a timeout for the answer.

Disabled by default. Enable per-scan with ``NEO_HUMAN_ASSIST=1``; when disabled
every call is a cheap no-op so unattended scans never stall waiting on a human.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_AGENT = "human-assist"


def enabled() -> bool:
    return os.getenv("NEO_HUMAN_ASSIST", "0").strip() == "1"


def _bb(scan_id: str, title: str, data: Dict[str, Any], ref: str = "") -> None:
    try:
        from core.orchestration import blackboard
        blackboard.post(scan_id, _AGENT, "note", title, data, ref=ref)
    except Exception:
        pass


def request(scan_id: str, prompt: str, *, kind: str = "assist",
            ref: str = "", context: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Post a task for a human (non-blocking). Returns the request_id, or None
    when HITL is disabled / no scan_id. Idempotent per ``ref``."""
    if not enabled() or not scan_id:
        return None
    request_id = ("hr_" + uuid.uuid4().hex[:12])
    try:
        from core.database.pg_store import HumanRequestRepo
        HumanRequestRepo.create(scan_id, request_id, prompt, kind=kind, ref=ref,
                                context=context or {})
    except Exception as e:
        logger.debug("[HumanAssist] create failed: %s", e)
        return None
    _bb(scan_id, f"Human assist requested: {prompt[:80]}",
        {"request_id": request_id, "kind": kind, "ref": ref, **(context or {})},
        ref=ref or request_id)
    logger.info("[HumanAssist] requested (%s) %s", kind, prompt[:100])
    return request_id


def answer(scan_id: str, request_id: str, text: str, solved: bool = False) -> bool:
    """Record a human's answer (called by the API/UI)."""
    try:
        from core.database.pg_store import HumanRequestRepo
        ok = HumanRequestRepo.answer(scan_id, request_id, text, solved=solved)
    except Exception as e:
        logger.debug("[HumanAssist] answer failed: %s", e)
        return False
    if ok:
        _bb(scan_id, f"Human answered {request_id} (solved={solved})",
            {"request_id": request_id, "solved": solved})
    return ok


def pending(scan_id: str) -> List[Dict[str, Any]]:
    try:
        from core.database.pg_store import HumanRequestRepo
        return HumanRequestRepo.list_by_scan(scan_id, status="pending")
    except Exception:
        return []


async def ask(scan_id: str, prompt: str, *, kind: str = "assist", ref: str = "",
              context: Optional[Dict[str, Any]] = None,
              timeout_s: float = 0.0) -> Optional[str]:
    """BLOCKING assist: post a request and wait up to ``timeout_s`` for a human
    answer (default 0 = don't wait → behaves like ``request``). Returns the
    answer text, or None on timeout / disabled. Poll interval is gentle so a
    long wait costs almost nothing. Use only for a value the probe needs inline
    (e.g. a CAPTCHA); prefer the non-blocking ``request`` for offloaded tasks."""
    rid = request(scan_id, prompt, kind=kind, ref=ref, context=context)
    if rid is None:
        return None
    if timeout_s <= 0:
        return None
    # allow an env cap so an operator can bound how long any probe may block
    try:
        cap = float(os.getenv("NEO_HUMAN_ASSIST_MAX_WAIT", "600"))
    except ValueError:
        cap = 600.0
    deadline = time.time() + min(timeout_s, cap)
    import asyncio
    from core.database.pg_store import HumanRequestRepo
    while time.time() < deadline:
        await asyncio.sleep(3.0)
        row = HumanRequestRepo.get(scan_id, rid)
        if row and row.get("status") == "answered":
            return row.get("answer") or ""
    logger.info("[HumanAssist] request %s timed out after %.0fs", rid, timeout_s)
    return None
