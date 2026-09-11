"""Phase 6.1 — persistent LLM cost tracking.

``TokenBudget`` (agents.universal_llm_harness) tracks spend for the life of a
process. This adds a durable, per-scan cost log so cost survives the run and can
be queried by the dashboard (``GET /api/scans/{scan_id}/cost``).

An injectable ``persist`` callback writes each entry to the ``llm_cost_log`` DB
table in production; in-memory aggregation makes it fully unit-testable with no
DB. ``from_budget`` ingests a TokenBudget's requests without touching that hot
class.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CostLogEntry:
    scan_id: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class LLMCostLog:

    def __init__(self, persist: Optional[Callable[[CostLogEntry], None]] = None):
        self._entries: List[CostLogEntry] = []
        self._persist = persist
        self._lock = threading.RLock()

    def record(self, scan_id: str, provider: str, model: str, *,
               input_tokens: int = 0, output_tokens: int = 0, cost_usd: float = 0.0,
               timestamp: str = "") -> CostLogEntry:
        entry = CostLogEntry(scan_id=scan_id, provider=provider, model=model,
                             input_tokens=input_tokens, output_tokens=output_tokens,
                             cost_usd=cost_usd, timestamp=timestamp or
                             datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._entries.append(entry)
        if self._persist:
            try:
                self._persist(entry)
            except Exception as e:   # persistence must never break the scan
                logger.warning("cost_log: persist failed (%s)", e)
        return entry

    def record_metric(self, scan_id: str, metric: Any) -> CostLogEntry:
        """Record from a UsageMetrics-like object."""
        return self.record(
            scan_id, getattr(metric, "provider", ""), getattr(metric, "model", ""),
            input_tokens=getattr(metric, "input_tokens", 0),
            output_tokens=getattr(metric, "output_tokens", 0),
            cost_usd=getattr(metric, "cost_usd", 0.0),
            timestamp=getattr(metric, "timestamp", "") or "")

    def from_budget(self, budget: Any, scan_id: str) -> int:
        """Ingest all requests recorded on a TokenBudget for `scan_id`."""
        n = 0
        for m in getattr(budget, "requests", []) or []:
            self.record_metric(scan_id, m)
            n += 1
        return n

    def entries_for(self, scan_id: str) -> List[CostLogEntry]:
        with self._lock:
            return [e for e in self._entries if e.scan_id == scan_id]

    def get_total_cost(self, scan_id: str) -> float:
        return round(sum(e.cost_usd for e in self.entries_for(scan_id)), 6)

    def get_cost_breakdown(self, scan_id: str) -> Dict[str, Any]:
        entries = self.entries_for(scan_id)
        by_model: Dict[str, Dict[str, Any]] = {}
        by_provider: Dict[str, float] = {}
        total_in = total_out = 0
        for e in entries:
            key = f"{e.provider}/{e.model}"
            b = by_model.setdefault(key, {"requests": 0, "input_tokens": 0,
                                          "output_tokens": 0, "cost_usd": 0.0})
            b["requests"] += 1
            b["input_tokens"] += e.input_tokens
            b["output_tokens"] += e.output_tokens
            b["cost_usd"] = round(b["cost_usd"] + e.cost_usd, 6)
            by_provider[e.provider] = round(by_provider.get(e.provider, 0.0) + e.cost_usd, 6)
            total_in += e.input_tokens
            total_out += e.output_tokens
        return {
            "scan_id": scan_id,
            "total_cost_usd": self.get_total_cost(scan_id),
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "requests": len(entries),
            "by_model": by_model,
            "by_provider": by_provider,
        }

    def to_dicts(self, scan_id: str) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.entries_for(scan_id)]


_GLOBAL_COST_LOG: Optional[LLMCostLog] = None


def get_cost_log() -> LLMCostLog:
    """Process-wide cost log shared by the harness and the dashboard API."""
    global _GLOBAL_COST_LOG
    if _GLOBAL_COST_LOG is None:
        _GLOBAL_COST_LOG = LLMCostLog(persist=_db_persist)
    return _GLOBAL_COST_LOG


def _db_persist(entry: CostLogEntry) -> None:
    """Best-effort insert into the llm_cost_log table (no-op without a DB)."""
    try:
        from core.memory.database import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO llm_cost_log "
                    "(scan_id, provider, model, input_tokens, output_tokens, cost_usd, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (entry.scan_id, entry.provider, entry.model, entry.input_tokens,
                     entry.output_tokens, entry.cost_usd, entry.timestamp))
                conn.commit()
    except Exception as e:
        logger.debug("cost_log: DB persist skipped (%s)", e)
