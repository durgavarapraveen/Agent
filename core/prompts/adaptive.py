"""
Adaptive Prompt Engineering Engine (Phase 3 Module 3.2).
Loads industry-specific variants (healthcare, finance, retail, default), enforces tier-based depth rules
(shallow, poc, deep), dynamically injects error recovery instructions, and tracks A/B prompt performance.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Any
from core.database import DatabaseManager

logger = logging.getLogger(__name__)

DEPTH_TOOL_CONSTRAINTS = {
    "shallow": {
        "payload_percentage": "10%",
        "allowed_tools": ["nmap", "web_info_gatherer"],
        "description": "Shallow scan: only run nmap and basic web info gathering."
    },
    "poc": {
        "payload_percentage": "50%",
        "allowed_tools": ["nmap", "web_info_gatherer", "nuclei", "gobuster"],
        "description": "PoC scan: add nuclei and gobuster for proof-of-concept verification."
    },
    "deep": {
        "payload_percentage": "100%",
        "allowed_tools": ["nmap", "web_info_gatherer", "nuclei", "gobuster", "full_fuzzer", "exploit_chainer", "business_logic_tester"],
        "description": "Exhaustive deep scan: add full fuzzing, exploit chaining, and business logic tests."
    }
}

RECOVERY_INSTRUCTIONS = {
    "connectiontimeout": "RECOVERY INSTRUCTION: Tool timed out. Increase timeout to 120 seconds and retry.",
    "timeout": "RECOVERY INSTRUCTION: Tool timed out. Increase timeout to 120 seconds and retry.",
    "403": "RECOVERY INSTRUCTION: Received HTTP 403 Forbidden. Switch to a different User-Agent and use a slower delay (2s).",
    "forbidden": "RECOVERY INSTRUCTION: Received HTTP 403 Forbidden. Switch to a different User-Agent and use a slower delay (2s).",
    "waf": "RECOVERY INSTRUCTION: WAF Block detected. Use generic, non-signature payloads (e.g., test instead of <script>alert(1)</script>).",
    "waf block": "RECOVERY INSTRUCTION: WAF Block detected. Use generic, non-signature payloads (e.g., test instead of <script>alert(1)</script>)."
}


class AdaptivePromptEngine:
    """Manages industry variants, depth instructions, error recovery, and A/B test refinement."""

    def __init__(self, variants_dir: str = "core/prompts/prompt_variants", db_path: str = "prompt_ab_tests.sqlite"):
        self.variants_dir = variants_dir
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS prompt_ab_runs (
                            id SERIAL PRIMARY KEY,
                            variant_key TEXT,
                            target_type TEXT,
                            findings_count INTEGER,
                            success_rate REAL,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    conn.commit()
        except Exception as e:
            logger.error(f"[AdaptivePrompt] DB init error: {e}")

    def load_industry_variant(self, industry: str = "default") -> str:
        """Load base prompt template for healthcare, finance, retail, or default."""
        ind_clean = (industry or "default").strip().lower()
        variant_path = os.path.join(self.variants_dir, ind_clean, "base.txt")

        if not os.path.exists(variant_path):
            variant_path = os.path.join(self.variants_dir, "default", "base.txt")

        if os.path.exists(variant_path):
            try:
                with open(variant_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"[AdaptivePrompt] Failed reading variant {variant_path}: {e}")

        return f"# Default Security Assessment Base Prompt for {ind_clean.upper()}"

    def build_prompt(self, industry: str = "default", depth: str = "poc", error_context: Optional[str] = None) -> str:
        """
        Build complete adaptive prompt incorporating industry variant, depth constraints,
        and dynamic error recovery instructions.
        """
        base = self.load_industry_variant(industry)
        depth_clean = (depth or "poc").strip().lower()
        depth_spec = DEPTH_TOOL_CONSTRAINTS.get(depth_clean, DEPTH_TOOL_CONSTRAINTS["poc"])

        depth_block = (
            f"\n\n=== SCAN DEPTH: {depth_clean.upper()} ({depth_spec['payload_percentage']} Payloads) ===\n"
            f"{depth_spec['description']}\n"
            f"Allowed Tools: {', '.join(depth_spec['allowed_tools'])}"
        )

        recovery_block = ""
        if error_context:
            err_lower = error_context.lower()
            for pattern, rec in RECOVERY_INSTRUCTIONS.items():
                if pattern in err_lower:
                    recovery_block += f"\n\n=== ERROR RECOVERY ACTIVE ===\n{rec}"
                    break

        full_prompt = base + depth_block + recovery_block
        return full_prompt

    def log_run_result(self, variant_key: str, target_type: str, findings_count: int, success_rate: float):
        """Log prompt variant run result for A/B testing analysis."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO prompt_ab_runs (variant_key, target_type, findings_count, success_rate)
                        VALUES (%s, %s, %s, %s)
                    """, (variant_key, target_type, findings_count, success_rate))
                    conn.commit()
        except Exception as e:
            logger.debug(f"[AdaptivePrompt] Log run result error: {e}")

    def suggest_best_variant(self, target_type: str) -> Optional[str]:
        """
        After 10 runs of a target type, auto-suggest the best-performing prompt variant via a CLI message:
        "Suggested prompt: finance/deep based on 85% success rate across 10 scans."
        """
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM prompt_ab_runs WHERE target_type=%s", (target_type,))
                    count = cur.fetchone()[0]

                    if count >= 10:
                        cur.execute("""
                            SELECT variant_key, AVG(success_rate) as avg_sr
                            FROM prompt_ab_runs
                            WHERE target_type=%s
                            GROUP BY variant_key
                            ORDER BY avg_sr DESC
                            LIMIT 1
                        """, (target_type,))
                        row = cur.fetchone()
                        if row:
                            variant_key, avg_sr = row[0], row[1]
                            suggestion = f"Suggested prompt: {variant_key} based on {int(avg_sr * 100)}% success rate across {count} scans."
                            print(f"[A/B Prompt Optimization] {suggestion}")
                            return suggestion
        except Exception as e:
            logger.debug(f"[AdaptivePrompt] Suggestion error: {e}")

        return None
