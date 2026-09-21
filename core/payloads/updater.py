from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from core.payloads.catalog import PayloadCatalog, get_payload_catalog

logger = logging.getLogger(__name__)

# Marker for interval-guarded auto-sync (§6 "optional daily scheduled pull").
# Calling update_all on every scan start is cheap because it re-pulls/re-ingests
# at most once per PAYLOAD_SYNC_INTERVAL_HOURS.
_SYNC_MARKER = os.getenv("PAYLOAD_SYNC_MARKER",
                         os.path.join("data", "payloads", ".last_sync"))

# Default local cache root — sources auto-clone here when no explicit *_DIR env is
# set, so a fresh install needs zero manual `git clone`.
_CACHE_ROOT = os.getenv("PAYLOAD_CACHE_DIR", os.path.join("data", "payloads"))

# Normalizer version — bump when ingestion parsing changes so a re-ingest is
# forced even if the source commit is unchanged. Recorded in the manifest.
NORMALIZER_VERSION = os.getenv("PAYLOAD_NORMALIZER_VERSION", "1")

# Configurable source repositories (spec §3: configurable repository URL).
_SOURCES = {
    "patt": {
        "url": os.getenv("PATT_REPO_URL",
                         "https://github.com/swisskyrepo/PayloadsAllTheThings.git"),
        "dir_env": "PAYLOADS_ALL_THE_THINGS_DIR",
        "default_dir": os.path.join(_CACHE_ROOT, "PayloadsAllTheThings"),
        "pin_env": "PATT_COMMIT",
    },
    "nuclei": {
        "url": os.getenv("NUCLEI_TEMPLATES_URL",
                         "https://github.com/projectdiscovery/nuclei-templates.git"),
        "dir_env": "NUCLEI_TEMPLATES_DIR",
        "default_dir": os.path.join(_CACHE_ROOT, "nuclei-templates"),
        "pin_env": "NUCLEI_COMMIT",
    },
}


def nuclei_templates_dir() -> str:
    """Resolved nuclei-templates directory (env override → default cache dir),
    but only if it actually exists and is non-empty. Returns "" otherwise so
    callers can omit -t and let nuclei fall back to its own managed templates.
    Single source of truth for both nuclei command builders."""
    cfg = _SOURCES["nuclei"]
    d = os.getenv(cfg["dir_env"]) or cfg["default_dir"]
    try:
        if os.path.isdir(d) and any(os.scandir(d)):
            return d
    except Exception:
        pass
    return ""


class PayloadUpdater:
    """Keeps the PayloadCatalog synced with community sources (P1 auto-update).

    Behaviour (spec §3 — no manual clone required):
      * source missing        → shallow ``git clone`` into the local cache
      * source present         → ``git fetch`` + ``git pull --ff-only``
      * pinned commit          → ``git checkout <commit>`` for reproducibility
      * commit unchanged AND normalizer unchanged → skip expensive re-ingestion
      * every step is guarded  → a network/git failure never destroys a working
                                  catalog and never breaks a scan

    Each source records a manifest (repo/commit/updated_at/normalizer_version/
    payload_count) under the local cache so runs are reproducible and auditable.
    Auto-clone is opt-out via PAYLOAD_AUTO_CLONE=0 (offline/air-gapped).
    """

    def __init__(self, catalog: PayloadCatalog = None):
        self.catalog = catalog or get_payload_catalog()

    # ── git helpers (all best-effort) ─────────────────────────────────────
    @staticmethod
    def _auto_clone_enabled() -> bool:
        return os.getenv("PAYLOAD_AUTO_CLONE", "1").strip() != "0"

    def _ensure_repo(self, path: str, url: str) -> bool:
        """Ensure a git checkout exists at ``path`` (clone if missing). Returns
        True if a usable checkout is present afterwards. Never raises."""
        if os.path.isdir(os.path.join(path, ".git")):
            return True
        if not self._auto_clone_enabled():
            return os.path.isdir(path)  # pre-provisioned dir without .git
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            depth = os.getenv("PAYLOAD_CLONE_DEPTH", "1")
            cmd = ["git", "clone"]
            if depth and depth != "0":
                cmd += ["--depth", depth]
            cmd += [url, path]
            logger.info("PayloadUpdater: cloning %s → %s", url, path)
            r = subprocess.run(cmd, capture_output=True, timeout=600, check=False)
            if r.returncode == 0 and os.path.isdir(os.path.join(path, ".git")):
                return True
            logger.warning("PayloadUpdater: clone failed (%s): %s", url,
                           (r.stderr or b"").decode("utf-8", "ignore")[:200])
        except Exception as e:
            logger.warning("PayloadUpdater: clone error %s: %s", url, e)
        return os.path.isdir(os.path.join(path, ".git"))

    def _git_head(self, path: str) -> str:
        try:
            r = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                               capture_output=True, timeout=30, check=False)
            if r.returncode == 0:
                return r.stdout.decode("utf-8", "ignore").strip()
        except Exception as e:
            logger.debug("git rev-parse %s failed: %s", path, e)
        return ""

    def _git_update(self, path: str, pin_commit: str = "") -> None:
        """Fetch + fast-forward, or checkout a pinned commit for reproducibility.
        A pull that cannot fast-forward is left as-is (working catalog preserved)."""
        try:
            if not os.path.isdir(os.path.join(path, ".git")):
                return
            if pin_commit:
                subprocess.run(["git", "-C", path, "fetch", "--depth", "1",
                                "origin", pin_commit],
                               capture_output=True, timeout=300, check=False)
                subprocess.run(["git", "-C", path, "checkout", pin_commit],
                               capture_output=True, timeout=120, check=False)
                return
            subprocess.run(["git", "-C", path, "fetch", "--all", "--tags"],
                           capture_output=True, timeout=300, check=False)
            subprocess.run(["git", "-C", path, "pull", "--ff-only"],
                           capture_output=True, timeout=300, check=False)
        except Exception as e:
            logger.debug("git update %s failed: %s", path, e)

    # ── manifest (spec §3 / §25 reproducibility) ──────────────────────────
    @staticmethod
    def _manifest_path(source: str) -> str:
        return os.path.join(_CACHE_ROOT, f"{source}_manifest.json")

    def _read_manifest(self, source: str) -> Dict:
        try:
            with open(self._manifest_path(source), "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_manifest(self, source: str, repository: str, commit: str,
                        payload_count: int) -> None:
        data = {
            "source": source,
            "repository": repository,
            "commit": commit,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "normalizer_version": NORMALIZER_VERSION,
            "payload_count": payload_count,
        }
        try:
            os.makedirs(_CACHE_ROOT, exist_ok=True)
            with open(self._manifest_path(source), "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info("PayloadUpdater: manifest %s commit=%s count=%s",
                        source, commit[:12] or "?", payload_count)
        except OSError as e:
            logger.debug("manifest write failed (%s): %s", source, e)

    def _catalog_size(self) -> int:
        for m in ("count", "size", "__len__"):
            fn = getattr(self.catalog, m, None)
            if callable(fn):
                try:
                    return int(fn())
                except Exception:
                    pass
        return 0

    def _sync_git_source(self, source: str, ingest) -> int:
        """Clone/update one git source and ingest only when its commit (or the
        normalizer version) changed. ``ingest`` is a callable(path)->int. Returns
        payloads ingested this run (0 if skipped or unavailable)."""
        cfg = _SOURCES[source]
        path = os.getenv(cfg["dir_env"]) or cfg["default_dir"]
        url = cfg["url"]
        pin = os.getenv(cfg["pin_env"], "").strip()
        if not self._ensure_repo(path, url):
            logger.info("PayloadUpdater: %s unavailable (no checkout, auto-clone off/failed)", source)
            return 0
        before = self._git_head(path)
        self._git_update(path, pin_commit=pin)
        after = self._git_head(path)
        prev = self._read_manifest(source)
        unchanged = (after and after == prev.get("commit")
                     and prev.get("normalizer_version") == NORMALIZER_VERSION)
        force = os.getenv("PAYLOAD_FORCE_INGEST", "0").strip() != "0"
        if unchanged and not force:
            logger.info("PayloadUpdater: %s unchanged @ %s — skip ingest",
                        source, (after or "?")[:12])
            return 0
        try:
            n = int(ingest(path) or 0)
        except Exception as e:
            logger.warning("PayloadUpdater: %s ingest failed: %s", source, e)
            return 0
        self._write_manifest(source, url, after or before, self._catalog_size())
        return n

    async def update_all(self) -> Dict[str, int]:
        return self.update_all_sync()

    # ── interval-guarded auto-sync (safe to call on every scan start) ────
    def _due(self, interval_hours: float) -> bool:
        try:
            last = os.path.getmtime(_SYNC_MARKER)
            return (time.time() - last) >= interval_hours * 3600
        except OSError:
            return True  # never synced

    def _mark_synced(self) -> None:
        try:
            os.makedirs(os.path.dirname(_SYNC_MARKER) or ".", exist_ok=True)
            with open(_SYNC_MARKER, "w", encoding="utf-8") as f:
                f.write(str(int(time.time())))
        except OSError as e:
            logger.debug("sync marker write failed: %s", e)

    def maybe_update(self, interval_hours: float = None) -> Dict[str, int]:
        """Pull + re-ingest only if the last sync is older than the interval
        (default PAYLOAD_SYNC_INTERVAL_HOURS or 24h). Returns {} when skipped."""
        if interval_hours is None:
            try:
                interval_hours = float(os.getenv("PAYLOAD_SYNC_INTERVAL_HOURS", "24"))
            except ValueError:
                interval_hours = 24.0
        if not self._due(interval_hours):
            logger.debug("PayloadUpdater: sync not due (interval %.1fh)", interval_hours)
            return {}
        counts = self.update_all_sync()
        self._mark_synced()
        return counts

    def update_all_sync(self) -> Dict[str, int]:
        counts = {"nuclei": 0, "patt": 0, "custom": 0}

        # PATT + nuclei: auto-clone/fetch + commit-gated ingest via manifest.
        counts["patt"] = self._sync_git_source(
            "patt", lambda p: self.catalog.ingest_payloads_all_the_things(p))
        counts["nuclei"] = self._sync_git_source(
            "nuclei", lambda p: self.catalog.ingest_nuclei_templates(p))

        # Custom local YAML (non-git): ingest as before.
        custom = os.getenv("CUSTOM_PAYLOADS_DIR")
        if custom and os.path.isdir(custom):
            try:
                for fn in os.listdir(custom):
                    if fn.endswith((".yaml", ".yml")):
                        counts["custom"] += self.catalog.ingest_custom_yaml(
                            os.path.join(custom, fn))
            except Exception as e:
                logger.warning("custom ingest failed: %s", e)

        logger.info("PayloadUpdater: %s", counts)
        return counts
