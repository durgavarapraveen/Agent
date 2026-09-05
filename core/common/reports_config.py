"""Centralised reports-directory gate.

The `reports/` folder is opt-in. Set `REPORTS_ENABLED=1` to re-enable
report/artefact writes. When disabled (default), report writers no-op:
directory creation is skipped and writers should use `reports_enabled()`
before touching disk.
"""
from __future__ import annotations

import os
from pathlib import Path


def reports_enabled() -> bool:
    """True when the caller may write to the reports/ tree."""
    return os.getenv("REPORTS_ENABLED", "0").lower() in ("1", "true", "yes", "on")


def reports_dir() -> Path:
    """Canonical reports root — honour `REPORTS_DIR` when set,
    fall back to `reports/`. Callers must still check `reports_enabled()`
    before writing."""
    return Path(os.getenv("REPORTS_DIR", "reports"))


def ensure_reports_dir() -> Path | None:
    """Create the reports directory if writes are enabled; return the path,
    or `None` when reports are disabled."""
    if not reports_enabled():
        return None
    p = reports_dir()
    p.mkdir(parents=True, exist_ok=True)
    return p
