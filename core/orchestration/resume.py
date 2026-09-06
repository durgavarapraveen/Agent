"""Idempotent scan resume from checkpoint.

After every completed phase we snapshot the scan's SharedContext into
`.antigravity/checkpoints/<scan_id>.enc` via `SecureCheckpoint`. On crash-
recovery boot, `ScanRepo.bootstrap_recover` flips the orphaned scan row to
`failed`; the operator then re-runs `python main.py --resume --scan-id <id>`
and this module fast-forwards through the phases that were already checkpointed.

Contract:
  save_checkpoint(scan_id, ctx, phase, phase_index)  — after each phase
  load_checkpoint(scan_id) -> (ctx_dict, next_phase_index)  — on resume
  clear_checkpoint(scan_id)                          — on successful finish

Every operation is best-effort; a checkpoint I/O failure never blocks the
running scan. The checkpoint is encrypted with the current `ENCRYPTION_KEY`
and carries a `key_version` marker so key rotation surfaces a clear error
rather than opaque decrypt failure.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.checkpointing.secure_checkpoint import SecureCheckpoint

logger = logging.getLogger(__name__)


_CHECKPOINT_DIR = Path(".antigravity/checkpoints")


def _path_for(scan_id: str) -> Path:
    _CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    # Sanitize scan_id — same rule as reporting_engine.
    import re as _re
    safe = _re.sub(r"[^A-Za-z0-9._-]+", "_", str(scan_id)).strip("._") or "unnamed"
    return _CHECKPOINT_DIR / f"{safe}.enc"


def _serialise_ctx(ctx: Any) -> Dict[str, Any]:
    """Convert the SharedContext to a JSON-safe dict for checkpointing.
    Only picks small, deterministic fields — no LLM histories, no attack
    graphs. On resume the graph is rebuilt from the persisted findings."""
    def _get(name):
        v = getattr(ctx, name, None)
        if v is None:
            return None
        if isinstance(v, (list, dict, str, int, float, bool)):
            return v
        return str(v)

    return {
        "target": _get("target"),
        "scope": _get("scope"),
        "subdomains": _get("subdomains") or [],
        "ips": _get("ips") or [],
        "ports": _get("ports") or [],
        "technologies": _get("technologies") or {},
        "directories": _get("directories") or [],
        "vulnerabilities_count": len(getattr(ctx, "vulnerabilities", []) or []),
    }


def save_checkpoint(scan_id: str, ctx: Any, phase: str, phase_index: int) -> bool:
    """Write a checkpoint after `phase` completes. Returns True on success."""
    try:
        state = {
            "scan_id": scan_id,
            "last_phase": phase,
            "phase_index": int(phase_index),
            "ctx": _serialise_ctx(ctx),
        }
        cp = SecureCheckpoint(str(_path_for(scan_id)))
        cp.save_checkpoint(state)
        logger.info("Scan checkpoint saved: scan_id=%s phase=%s idx=%d",
                    scan_id, phase, phase_index)
        return True
    except Exception as e:
        logger.warning("Scan checkpoint save failed: %s", e)
        return False


def load_checkpoint(scan_id: str) -> Optional[Tuple[Dict[str, Any], int]]:
    """Return `(ctx_dict, next_phase_index)` when a checkpoint exists and
    decrypts successfully; None otherwise. Any error is logged and treated
    as "no checkpoint" so a fresh scan starts."""
    p = _path_for(scan_id)
    if not p.exists():
        return None
    try:
        cp = SecureCheckpoint(str(p))
        state = cp.load_checkpoint()
        next_idx = int(state.get("phase_index", 0)) + 1
        return state.get("ctx") or {}, next_idx
    except Exception as e:
        logger.warning("Scan checkpoint load failed for %s: %s", scan_id, e)
        return None


def clear_checkpoint(scan_id: str) -> None:
    p = _path_for(scan_id)
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass
