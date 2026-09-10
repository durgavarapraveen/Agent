from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


def _cleanup_enabled() -> bool:
    return os.getenv("SCAN_CLEANUP_ENABLED", "1").lower() in ("1", "true", "yes", "on")


# ── Kali container ─────────────────────────────────────────────────────

# Prefixes/paths inside the container that are safe to wipe. NEVER include
# `/tmp/*` unqualified — that would nuke every tool's session state including
# other scans running concurrently. Every entry here matches only files this
# codebase creates.
KALI_TMP_PATTERNS = (
    # Screenshots (headless chromium output)
    "/tmp/*.png",
    "/tmp/*.html",
    # credential_spray artefacts
    "/tmp/spray_*.html", "/tmp/spray_*.txt",
    # API schema probes
    "/tmp/schema_probe.txt",
    # Generic scan-scratch directory (if any tool wrote there)
    "/tmp/ag_scan_*",
    # Nuclei per-run cache (project-mode)
    "/root/.config/nuclei/scans/*",
    # sqlmap per-run session
    "/root/.sqlmap/output/*",
    # ffuf resume files
    "/tmp/ffuf-*",
)


def cleanup_kali_container(container: str = None) -> dict:
    from agents.kali_executor import KaliDockerExecutor

    if not _cleanup_enabled():
        return {"skipped": True, "reason": "SCAN_CLEANUP_ENABLED=0"}

    container = container or KaliDockerExecutor.get_container(auto_create=False)
    if not container:
        return {"skipped": True, "reason": "no container"}

    removed = []
    errors = []

    for pattern in KALI_TMP_PATTERNS:
        base_dir = os.path.dirname(pattern)
        name_pat = os.path.basename(pattern)

        cmd = [
            "docker", "exec", container,
            "find", base_dir, "-maxdepth", "1", "-name", name_pat,
            "-exec", "rm", "-rf", "{}", "+"
        ]
        try:
            result = subprocess.run(
                cmd,
                shell=False, capture_output=True, encoding="utf-8",
                errors="replace", timeout=30,
            )
            if result.returncode == 0:
                removed.append(pattern)
            else:
                # 'find' returns an error if base_dir doesn't exist. Ignore that.
                if "No such file or directory" not in (result.stderr or ""):
                    errors.append(f"docker exec rc={result.returncode}: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            errors.append(f"cleanup timed out for {pattern}")
        except Exception as e:
            errors.append(str(e))

    logger.info(f"[ScanCleanup] Kali container: removed {len(removed)} path(s), "
                f"errors={len(errors)}")
    return {"container": container, "removed": removed, "errors": errors}


# ── Host-side scratch ──────────────────────────────────────────────────

# Prefixes for `tempfile.mkdtemp` that this codebase uses. Cleared at
# scan end.
HOST_MKDTEMP_PREFIXES = ("ag_screenshot_", "detonate_")


def cleanup_host_scratch(scan_id: str = "") -> dict:
    if not _cleanup_enabled():
        return {"skipped": True, "reason": "SCAN_CLEANUP_ENABLED=0"}

    import time
    removed = []
    now = time.time()
    tmproot = Path(tempfile.gettempdir())
    for entry in tmproot.iterdir() if tmproot.exists() else []:
        try:
            if not entry.is_dir():
                continue
            if not any(entry.name.startswith(p) for p in HOST_MKDTEMP_PREFIXES):
                continue
            # Use mtime (Windows st_ctime is creation, not change time)
            age_hours = (now - entry.stat().st_mtime) / 3600
            # Wipe if related to this scan OR older than 1h (finished agent)
            if (scan_id and scan_id in str(entry)) or age_hours > 1:
                shutil.rmtree(entry, ignore_errors=True)
                removed.append(str(entry))
        except Exception:
            pass

    # Per-scan loot subdirectory
    if scan_id:
        loot_dir = Path("loot") / scan_id
        if loot_dir.exists():
            try:
                shutil.rmtree(loot_dir, ignore_errors=True)
                removed.append(str(loot_dir))
            except Exception:
                pass

    logger.info(f"[ScanCleanup] Host scratch: removed {len(removed)} path(s)"
                f" for scan_id={scan_id or '<any>'}")
    return {"scan_id": scan_id, "removed": removed}


# ── Aggregate entry-point ──────────────────────────────────────────────

def cleanup_after_scan(scan_id: str = "", container: str = None) -> dict:
    if not _cleanup_enabled():
        return {"skipped": True, "reason": "SCAN_CLEANUP_ENABLED=0"}
    return {
        "scan_id": scan_id,
        "kali": cleanup_kali_container(container=container),
        "host": cleanup_host_scratch(scan_id=scan_id),
    }
