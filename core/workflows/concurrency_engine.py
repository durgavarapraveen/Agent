
import logging
import asyncio
from typing import Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ConcurrencyExperiment:
    experiment_id: str
    target_resource: str
    action: str
    workers: int = 5
    payloads: List[Dict[str, Any]] = None

class ConcurrencyEngine:
    """Barrier-based concurrency/race-condition engine with impact budgets."""

    DEFAULT_MAX_FANOUT = 20

    def __init__(self, impact_budget: int = 50, max_fanout: int = DEFAULT_MAX_FANOUT):
        self.impact_budget = impact_budget
        self.max_fanout = max_fanout
        self.experiments_run = 0
        
    async def _worker_task(self, worker_id: int, barrier: asyncio.Barrier, 
                           task_func: Callable[..., Awaitable[Any]], kwargs: Dict[str, Any]) -> Any:
        try:
            # Wait at the barrier so all workers fire at exactly the same time
            await barrier.wait()
            return await task_func(**kwargs)
        except Exception as e:
            logger.error(f"Worker {worker_id} failed: {e}")
            return {"error": str(e)}

    async def execute_race_condition_test(self, experiment: ConcurrencyExperiment, 
                                          test_func: Callable[..., Awaitable[Any]]) -> List[Any]:
        if self.experiments_run >= self.impact_budget:
            logger.warning("Concurrency impact budget exceeded, rejecting experiment.")
            return []
            
        self.experiments_run += 1
        
        num_workers = min(experiment.workers, self.max_fanout)
        barrier = asyncio.Barrier(num_workers)
        
        payloads = experiment.payloads or [{}] * num_workers
        
        # Extend payloads if necessary
        if len(payloads) < num_workers:
            payloads.extend([payloads[-1]] * (num_workers - len(payloads)))
            
        tasks = []
        for i in range(num_workers):
            kwargs = {"payload": payloads[i], "resource": experiment.target_resource, "action": experiment.action}
            task = asyncio.create_task(self._worker_task(i, barrier, test_func, kwargs))
            tasks.append(task)
            
        logger.info(f"Firing {num_workers} concurrent requests at {experiment.target_resource}")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

    def analyze_results(self, results: List[Any]) -> Dict[str, Any]:
        """
        Analyze results for race condition indicators (e.g. multiple successes where only 1 was expected).
        """
        successes = 0
        failures = 0
        
        for res in results:
            if isinstance(res, dict):
                if res.get("status") == "success":
                    successes += 1
                else:
                    failures += 1
                    
        return {
            "total": len(results),
            "successes": successes,
            "failures": failures,
            "race_condition_likely": successes > 1
        }
