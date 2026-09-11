"""Phase 8.2 — batch endpoint classification.

RECON classifies endpoints by risk; doing one LLM call per endpoint on a
500-endpoint site is 500 calls. This groups endpoints by path pattern and sends
20-50 per call, cutting classification calls to 10-25.

The grouping / prompt-building / response-parsing are pure; classification uses
an injectable async ``llm`` so it is testable with no live model.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.discovery.workflow_crawler import normalize_path

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 25
_RISK_LEVELS = {"critical", "high", "medium", "low", "info"}


def group_by_pattern(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for ep in endpoints:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        method = (ep.get("method", "GET") if isinstance(ep, dict) else "GET").upper()
        key = f"{method} {normalize_path(url)}"
        groups.setdefault(key, []).append(ep)
    return groups


def build_batch_prompt(patterns: List[str]) -> str:
    listing = "\n".join(f"{i+1}. {p}" for i, p in enumerate(patterns))
    return (
        "Classify each endpoint pattern by risk level (critical/high/medium/low/info) "
        "and likely vulnerability classes. Respond with JSON: "
        '{"classifications": [{"pattern": "...", "risk": "...", "vuln_classes": ["..."]}]}\n\n'
        f"Endpoint patterns:\n{listing}"
    )


def parse_batch_classification(response: Dict[str, Any],
                               patterns: List[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in (response or {}).get("classifications", []) or []:
        if not isinstance(item, dict):
            continue
        pat = item.get("pattern", "")
        risk = str(item.get("risk", "medium")).lower()
        if risk not in _RISK_LEVELS:
            risk = "medium"
        if pat in patterns:
            out[pat] = {"risk": risk, "vuln_classes": item.get("vuln_classes", [])}
    # Default any pattern the model skipped.
    for p in patterns:
        out.setdefault(p, {"risk": "medium", "vuln_classes": []})
    return out


class BatchClassifier:

    def __init__(self, llm: Any = None, batch_size: int = DEFAULT_BATCH_SIZE):
        self._llm = llm
        self.batch_size = batch_size
        self.calls = 0

    async def classify(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Return {endpoint-pattern: {risk, vuln_classes}}. One LLM call per
        batch of `batch_size` patterns instead of one per endpoint."""
        groups = group_by_pattern(endpoints)
        patterns = list(groups.keys())
        result: Dict[str, Dict[str, Any]] = {}

        for i in range(0, len(patterns), self.batch_size):
            batch = patterns[i:i + self.batch_size]
            classified = await self._classify_batch(batch)
            result.update(classified)
        return result

    async def _classify_batch(self, patterns: List[str]) -> Dict[str, Dict[str, Any]]:
        if self._llm is None:
            return {p: {"risk": "medium", "vuln_classes": []} for p in patterns}
        self.calls += 1
        try:
            data = await self._llm.generate_json(build_batch_prompt(patterns))
        except Exception as e:
            logger.warning("batch_classifier: LLM call failed (%s)", e)
            data = {}
        return parse_batch_classification(data, patterns)

    def estimated_call_savings(self, endpoints: List[Dict[str, Any]]) -> Dict[str, int]:
        groups = group_by_pattern(endpoints)
        n_patterns = len(groups)
        batched = max(1, (n_patterns + self.batch_size - 1) // self.batch_size)
        return {"endpoints": len(endpoints), "patterns": n_patterns,
                "per_endpoint_calls": len(endpoints), "batched_calls": batched,
                "calls_saved": max(0, len(endpoints) - batched)}
