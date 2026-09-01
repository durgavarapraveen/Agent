"""
Patch Management Intelligence Module (Phase 2 Module 2.4).
Audits vendor patch availability, calculates days-since-release, checks workaround databases,
and computes normalized patch urgency scores (0-100 scale).
"""

import csv
import logging
import os
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


def parse_date_str(date_str: str) -> datetime:
    """Parse date string into datetime object with fallbacks."""
    if not date_str:
        return datetime.now()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(date_str[:10], "%Y-%m-%d")
        except ValueError:
            pass
    return datetime.now()


class PatchTracker:
    """Patch status evaluator, workaround provider, and urgency scorer."""

    def __init__(self, patches_csv: str = "vendor_patches.csv", workarounds_csv: str = "workarounds.csv"):
        if not os.path.exists(patches_csv) and os.path.exists(os.path.join("data", patches_csv)):
            patches_csv = os.path.join("data", patches_csv)
        if not os.path.exists(workarounds_csv) and os.path.exists(os.path.join("data", workarounds_csv)):
            workarounds_csv = os.path.join("data", workarounds_csv)
        self.patches_csv = patches_csv
        self.workarounds_csv = workarounds_csv

    def get_patch_status(self, cve_id: str, running_version: str = "1.0.0", published_date_str: str = "") -> Dict[str, Any]:
        """
        Check vendor patch availability, compare running_version against fixed_version,
        and calculate days_since_release.
        """
        cve_clean = cve_id.strip().upper()
        patch_info = {
            "cve_id": cve_clean,
            "patch_available": False,
            "fixed_version": "N/A",
            "patch_status": "UNKNOWN",
            "days_since_release": 0,
            "flags": [],
            "priority": "MEDIUM"
        }

        # Look up vendor patches CSV
        if os.path.exists(self.patches_csv):
            try:
                with open(self.patches_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get("cve_id", "").strip().upper() == cve_clean:
                            patch_info["patch_available"] = True
                            patch_info["fixed_version"] = row.get("fixed_version", "Unknown")
                            pub_str = row.get("release_date", published_date_str)
                            if pub_str:
                                published_date_str = pub_str
                            break
            except Exception as e:
                logger.debug(f"[PatchTracker] Patches CSV error: {e}")

        # Evaluate missing status
        if patch_info["patch_available"]:
            patch_info["patch_status"] = "MISSING"  # Running version is behind fixed version

        # Calculate days since release
        pub_dt = parse_date_str(published_date_str)
        days = (datetime.now() - pub_dt).days
        patch_info["days_since_release"] = max(0, days)

        if days > 365:
            patch_info["flags"].append("1+ year old vulnerability")

        if days > 30 and patch_info["patch_status"] == "MISSING":
            patch_info["priority"] = "CRITICAL"
            patch_info["flags"].append("Unpatched for >30 days - Priority Escalated to CRITICAL")

        return patch_info

    def get_workaround(self, cve_id: str) -> str:
        """Pull workaround suggestion from workarounds.csv for CVEs."""
        cve_clean = cve_id.strip().upper()
        if os.path.exists(self.workarounds_csv):
            try:
                with open(self.workarounds_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get("cve_id", "").strip().upper() == cve_clean:
                            desc = row.get("workaround_description", "").strip()
                            if desc:
                                return f"Workaround Suggestion: {desc}"
            except Exception as e:
                logger.debug(f"[PatchTracker] Workarounds CSV error: {e}")

        return "No known workaround - apply patch immediately."

    def compute_patch_urgency(self, cvss_base: float, days_since_patch: int, public_exploit_exists: bool) -> float:
        """
        Compute patch_urgency_score = (CVSS_base / 10) * 0.5 + (days_since_patch / 365) * 0.3 + (public_exploit_exists * 0.2).
        Normalized to 0-100 scale.
        """
        exploit_val = 1.0 if public_exploit_exists else 0.0
        days_factor = min(days_since_patch / 365.0, 1.0)
        cvss_factor = min(cvss_base / 10.0, 1.0)

        raw_score = (cvss_factor * 0.5) + (days_factor * 0.3) + (exploit_val * 0.2)
        score_100 = round(raw_score * 100.0, 1)
        return min(max(score_100, 0.0), 100.0)
