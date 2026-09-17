from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Dict

from core.payloads.catalog import PayloadCatalog, get_payload_catalog

logger = logging.getLogger(__name__)

# Marker for interval-guarded auto-sync (§6 "optional daily scheduled pull").
# Calling update_all on every scan start is cheap because it re-pulls/re-ingests
# at most once per PAYLOAD_SYNC_INTERVAL_HOURS.
_SYNC_MARKER = os.getenv("PAYLOAD_SYNC_MARKER",
                         os.path.join("data", "payloads", ".last_sync"))


class PayloadUpdater:
    """Keeps the PayloadCatalog synced with community sources (P1 auto-update).

    Sources are git checkouts (submodules or clones) whose paths come from env:
      NUCLEI_TEMPLATES_DIR, PAYLOADS_ALL_THE_THINGS_DIR, CUSTOM_PAYLOADS_DIR
    On update it does a best-effort ``git pull`` then re-ingests. Safe to call on
    scan start; every step is guarded so a missing source never breaks a scan.
    """

    def __init__(self, catalog: PayloadCatalog = None):
        self.catalog = catalog or get_payload_catalog()

    def _git_pull(self, path: str) -> None:
        try:
            if os.path.isdir(os.path.join(path, ".git")):
                subprocess.run(["git", "-C", path, "pull", "--ff-only"],
                               capture_output=True, timeout=120, check=False)
        except Exception as e:
            logger.debug("git pull %s failed: %s", path, e)

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
        nuclei = os.getenv("NUCLEI_TEMPLATES_DIR")
        patt = os.getenv("PAYLOADS_ALL_THE_THINGS_DIR")
        custom = os.getenv("CUSTOM_PAYLOADS_DIR")

        if nuclei and os.path.isdir(nuclei):
            self._git_pull(nuclei)
            try:
                counts["nuclei"] = self.catalog.ingest_nuclei_templates(nuclei)
            except Exception as e:
                logger.warning("nuclei ingest failed: %s", e)
        if patt and os.path.isdir(patt):
            self._git_pull(patt)
            try:
                counts["patt"] = self.catalog.ingest_payloads_all_the_things(patt)
            except Exception as e:
                logger.warning("PATT ingest failed: %s", e)
        if custom and os.path.isdir(custom):
            try:
                for fn in os.listdir(custom):
                    if fn.endswith((".yaml", ".yml")):
                        counts["custom"] += self.catalog.ingest_custom_yaml(os.path.join(custom, fn))
            except Exception as e:
                logger.warning("custom ingest failed: %s", e)

        logger.info("PayloadUpdater: %s", counts)
        return counts
