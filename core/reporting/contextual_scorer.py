
import csv
import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, Tuple

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)


def parse_cvss_vector(vector_str: str) -> Dict[str, str]:
    metrics = {}
    if not vector_str:
        return metrics
    pattern = r"\b(AV|AC|PR|UI|S|C|I|A):([NLLHUPR])\b"
    matches = re.findall(pattern, vector_str)
    for key, val in matches:
        metrics[key] = val
    return metrics


def check_exploit_availability(cve_id: str, csv_path: str = "exploit_availability.csv") -> bool:
    if not os.path.exists(csv_path) and os.path.exists(os.path.join("data", csv_path)):
        csv_path = os.path.join("data", csv_path)
    if not cve_id or not os.path.exists(csv_path):
        return False
    cve_clean = cve_id.strip().upper()
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("cve_id", "").strip().upper() == cve_clean:
                    has_poc = str(row.get("has_public_poc", "")).lower() == "true"
                    has_msf = str(row.get("has_metasploit", "")).lower() == "true"
                    if has_poc or has_msf:
                        return True
    except Exception as e:
        logger.debug(f"[ContextualScorer] CSV exploit lookup error: {e}")
    return False


class ContextualScorer:

    def __init__(self, db_path: str = None, overrides_path: str = "overrides.json", audit_log_path: str = "audit_overrides.hashlog"):
        if not os.path.exists(overrides_path) and os.path.exists(os.path.join("data", overrides_path)):
            overrides_path = os.path.join("data", overrides_path)
        self.overrides_path = overrides_path
        self.audit_log_path = audit_log_path
        self.business_impact_multipliers = {
            "critical_asset": 1.5, "public_facing": 1.3, "internal_only": 1.0,
        }
        self.overrides = self._load_overrides()
        self.last_hash = "0" * 64

    def _load_overrides(self) -> Dict[str, float]:
        if os.path.exists(self.overrides_path):
            try:
                with open(self.overrides_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return {k.upper(): float(v) for k, v in data.items()}
            except Exception as e:
                logger.debug(f"[ContextualScorer] Overrides load error: {e}")
        return {}

    def _log_audit_entry(self, cve_id: str, old_score: float, new_score: float, user: str):
        timestamp = datetime.now().isoformat()
        entry_raw = f"{self.last_hash}|{timestamp}|{user}|{cve_id}|{old_score}|{new_score}"
        entry_hash = hashlib.sha256(entry_raw.encode("utf-8")).hexdigest()
        self.last_hash = entry_hash
        log_line = f"HASH={entry_hash} | TIMESTAMP={timestamp} | USER={user} | CVE={cve_id} | OLD={old_score} | NEW={new_score}\n"
        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"[AuditTrail] Failed to write hash-chain log: {e}")

    def get_cve_base_info(self, cve_id: str) -> Tuple[float, str]:
        cve_clean = cve_id.strip().upper()
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT cvss_v3_base_score, cvss_v3_vector FROM vuln_intel WHERE id = %s", (cve_clean,))
                    row = cur.fetchone()
                    if row:
                        return (float(row[0] or 7.5), str(row[1] or "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        except Exception:
            pass
        return (8.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def calculate_adjusted_score(self, cve_id: str, is_critical_asset: bool = False, is_public_facing: bool = False, csv_path: str = "exploit_availability.csv") -> float:
        cve_clean = cve_id.strip().upper()
        if cve_clean in self.overrides:
            return self.overrides[cve_clean]
        base_score, _ = self.get_cve_base_info(cve_clean)
        multiplier = 1.0
        if is_critical_asset:
            multiplier *= self.business_impact_multipliers["critical_asset"]
        if is_public_facing:
            multiplier *= self.business_impact_multipliers["public_facing"]
        bonus = 1.5 if check_exploit_availability(cve_clean, csv_path) else 0.0
        adjusted = min(base_score * multiplier + bonus, 10.0)
        return round(adjusted, 1)

    def apply_override(self, cve_id: str, new_score: float, user: str = "admin") -> float:
        cve_clean = cve_id.strip().upper()
        old_score = self.calculate_adjusted_score(cve_clean)
        new_score_clamped = min(max(float(new_score), 0.0), 10.0)
        self.overrides[cve_clean] = new_score_clamped
        try:
            with open(self.overrides_path, "w", encoding="utf-8") as f:
                json.dump(self.overrides, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to update overrides file: {e}")
        self._log_audit_entry(cve_clean, old_score, new_score_clamped, user)
        return new_score_clamped

    def format_cve_summary(self, cve_id: str, is_critical_asset: bool = False, is_public_facing: bool = False, csv_path: str = "exploit_availability.csv") -> str:
        cve_clean = cve_id.strip().upper()
        adj_score = self.calculate_adjusted_score(cve_clean, is_critical_asset, is_public_facing, csv_path)
        _, vector_str = self.get_cve_base_info(cve_clean)
        has_exploit = check_exploit_availability(cve_clean, csv_path)
        severity_label = "Low"
        if adj_score >= 9.0:
            severity_label = "Critical"
        elif adj_score >= 7.0:
            severity_label = "High"
        elif adj_score >= 4.0:
            severity_label = "Medium"
        exploit_str = "Public PoC available" if has_exploit else "No public exploit listed"
        return f"{cve_clean} | CVSS: {adj_score} ({severity_label}) | Vector: {vector_str} | Exploit: {exploit_str}"
