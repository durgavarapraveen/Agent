from __future__ import annotations
import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Iterable, List, Optional

logger = logging.getLogger(__name__)


class AgentTracker:

    def __init__(self, scan_id: str, agent_id: str, *,
                 label: str = "", phase: str = "", target: str = ""):
        self.scan_id = scan_id or ""
        self.agent_id = agent_id
        self.label = label or agent_id
        self.phase = phase
        self.target = target
        self.steps = 0
        self.findings_count = 0
        self.cost = 0.0
        self.current_tool = ""
        self.current_step = ""
        self.status = "queued"
        self._last_flush = 0.0

    def _flush(self, force: bool = False) -> None:
        # Rate-limit updates to ~once per second to avoid hammering the DB.
        now = time.monotonic()
        if not force and (now - self._last_flush) < 1.0:
            return
        self._last_flush = now
        if not self.scan_id:
            return
        try:
            from core.database.pg_store import LiveAgentRepo
            LiveAgentRepo.upsert(
                self.scan_id, self.agent_id,
                label=self.label, phase=self.phase, target=self.target,
                status=self.status, current_tool=self.current_tool,
                current_step=self.current_step,
                steps_taken=self.steps, findings_count=self.findings_count,
                cost_usd=self.cost,
                started=(self.status == "running"),
                finished=(self.status in ("completed", "failed")),
            )
        except Exception:
            pass

    def start(self, current_step: str = "") -> None:
        self.status = "running"
        self.current_step = current_step or "starting"
        logger.info(f"[agent={self.agent_id}] START phase={self.phase} target={self.target}")
        self._flush(force=True)

    def heartbeat(self, *, tool: Optional[str] = None, step: Optional[str] = None,
                   steps_taken: Optional[int] = None, findings_count: Optional[int] = None,
                   cost_usd: Optional[float] = None) -> None:
        if tool is not None:
            self.current_tool = tool
        if step is not None:
            self.current_step = step
        if steps_taken is not None:
            self.steps = steps_taken
        if findings_count is not None:
            self.findings_count = findings_count
        if cost_usd is not None:
            self.cost = cost_usd
        self._flush()

    def finish(self, *, status: str = "completed",
                findings: Optional[List] = None, cost_usd: Optional[float] = None,
                error: str = "") -> None:
        self.status = status
        if findings is not None:
            self.findings_count = len(findings)
        if cost_usd is not None:
            self.cost = cost_usd
        if error:
            self.current_step = f"error: {error[:120]}"
        else:
            self.current_step = "done"
        logger.info(f"[agent={self.agent_id}] {status.upper()} "
                    f"steps={self.steps} findings={self.findings_count} cost=${self.cost:.4f}")
        self._flush(force=True)


async def run_parallel_agents(items: Iterable[Any],
                                worker: Callable[[Any], Awaitable[Any]],
                                *, concurrency: int = 3,
                                label: str = "parallel_agents") -> List[Any]:
    items = list(items)
    if not items:
        return []
    concurrency = max(1, int(concurrency))
    logger.info(f"[{label}] Fanning out {len(items)} agents (concurrency={concurrency})")
    sem = asyncio.Semaphore(concurrency)

    async def _run(item):
        async with sem:
            try:
                return await worker(item)
            except Exception as e:
                logger.warning(f"[{label}] agent for {item!r} failed: {e}", exc_info=False)
                return None

    return await asyncio.gather(*(_run(i) for i in items))
