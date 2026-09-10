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
