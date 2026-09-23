from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _cleanup_enabled() -> bool:
    return os.getenv("SCAN_CLEANUP_ENABLED", "1").lower() in ("1", "true", "yes", "on")


# ── Kali container ─────────────────────────────────────────────────────

# Prefixes/paths inside the container that are safe to wipe. NEVER include
# `/tmp/*` unqualified — that would nuke every tool's session state including
# other scans running concurrently. Every entry here matches only files this
# codebase creates.
KALI_TMP_PATTERNS = (
    # ── Our own scan scratch in /tmp ──────────────────────────────────────
    "/tmp/*.png", "/tmp/*.html",                       # headless-chromium screenshots/pages
    "/tmp/spray_*.html", "/tmp/spray_*.txt",           # credential_spray artefacts
    "/tmp/spray_cookies.txt", "/tmp/spray_resp.html", "/tmp/spray_probe.html",
    "/tmp/schema_probe.txt",                           # API schema probes
    "/tmp/ag_scan_*", "/tmp/ag_*",                     # generic scan-scratch
    "/tmp/screenshot.png",
    # ── Per-tool OUTPUT/SESSION/LOG data written to /tmp (our adapters -o here) ─
    # Scoped by tool-name prefix / known extensions so a concurrent scan's config
    # is never touched. These are results/scratch, never installed tools or configs.
    "/tmp/ffuf-*", "/tmp/ffuf_*", "/tmp/ffuf*.json",
    "/tmp/nmap_*", "/tmp/*.gnmap", "/tmp/*.nmap", "/tmp/nmap*.xml",
    "/tmp/masscan_*", "/tmp/masscan*.xml", "/tmp/*.masscan",
    "/tmp/nuclei_*", "/tmp/nuclei*.json", "/tmp/nuclei*.txt",
    "/tmp/sqlmap_*", "/tmp/dalfox_*", "/tmp/dalfox*.txt",
    "/tmp/nikto_*", "/tmp/nikto*.txt", "/tmp/nikto*.xml",
    "/tmp/gobuster_*", "/tmp/gobuster*.txt", "/tmp/dirb_*", "/tmp/dirsearch_*",
    "/tmp/feroxbuster_*", "/tmp/ferox-*.state", "/tmp/ferox_*",
    "/tmp/katana_*", "/tmp/katana*.txt", "/tmp/whatweb_*", "/tmp/wafw00f_*",
    "/tmp/httpx_*", "/tmp/subfinder_*", "/tmp/amass_*", "/tmp/assetfinder_*",
    "/tmp/paramspider_*", "/tmp/arjun_*", "/tmp/wpscan_*", "/tmp/wpscan*.json",
    "/tmp/xsser_*", "/tmp/XSS*.xml", "/tmp/XSSreport*", "/tmp/commix_*",
    "/tmp/theharvester_*", "/tmp/harvest_*", "/tmp/sslscan_*", "/tmp/sslyze_*",
    "/tmp/testssl_*", "/tmp/dnsrecon_*", "/tmp/dnsenum_*", "/tmp/fierce_*",
    "/tmp/enum4linux_*", "/tmp/hydra_*", "/tmp/hydra.restore",
    # ── Per-tool OUTPUT/SESSION/LOG data in tool HOME dirs (CONTENTS only) ─────
    # We wipe results/sessions/logs, NEVER the tool's config, API keys, template
    # store or installed binaries (those live in sibling dirs we do not touch).
    "/root/.config/nuclei/scans/*",                    # nuclei per-run results (NOT templates/)
    "/root/.sqlmap/output/*",                          # sqlmap sessions (legacy path)
    "/root/.local/share/sqlmap/output/*",             # sqlmap sessions (current path)
    "/root/.dirsearch/reports/*",                       # dirsearch reports
    "/root/.local/share/commix/*",                     # commix sessions
    "/root/reports/*",                                  # tools that default to ~/reports
    "/root/ferox-*.state",                             # feroxbuster resume (cwd=/root)
    "/root/*.xml", "/root/*.gnmap", "/root/*.nmap",   # nmap outputs if run from /root
    "/root/XSSreport*", "/root/*.csv",                 # xsser / misc report artefacts
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

        # Run as root so files a tool wrote as root (nuclei scans, sqlmap output)
        # are traversable/deletable — a non-root exec hit "Permission denied" and
        # left them behind. `-mindepth 1` (with name '*') deletes directory CONTENTS,
        # never the dir itself, so the tool's output/session folder structure stays.
        depth = ["-mindepth", "1", "-maxdepth", "1"] if name_pat == "*" else ["-maxdepth", "1", "-name", name_pat]
        cmd = [
            "docker", "exec", "-u", "0", container,
            "find", base_dir, *depth,
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
