from __future__ import annotations

import os
from pathlib import Path


def reports_enabled() -> bool:
    return os.getenv("REPORTS_ENABLED", "0").lower() in ("1", "true", "yes", "on")


def reports_dir() -> Path:
    return Path(os.getenv("REPORTS_DIR", "reports"))


def ensure_reports_dir() -> Path | None:
    if not reports_enabled():
        return None
    p = reports_dir()
    p.mkdir(parents=True, exist_ok=True)
    return p
