import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Protocol
from core.benchmarking.juice_shop_mapper import JuiceShopChallengeMapper

logger = logging.getLogger(__name__)


@dataclass
class ChallengeResult:
    challenge_name: str = ""
    test_id: str = ""
    tested: bool = False
    confirmed: bool = False
    tool_used: str = ""
    error: str = ""


@dataclass
class BenchmarkResult:
    expected: int = 0
    tested: int = 0
    confirmed: int = 0
    coverage: float = 0.0
    challenge_results: List[ChallengeResult] = field(default_factory=list)

    def report(self) -> str:
        lines = [
            "=" * 60,
            "OWASP Juice Shop Benchmark Report",
            "=" * 60,
            f"Expected challenges : {self.expected}",
            f"Tested              : {self.tested}",
            f"Confirmed           : {self.confirmed}",
            f"Coverage            : {self.coverage:.1f}%",
            "-" * 60,
        ]

        confirmed_list = [r for r in self.challenge_results if r.confirmed]
        if confirmed_list:
            lines.append(f"Confirmed vulnerabilities ({len(confirmed_list)}):")
            for r in confirmed_list:
                lines.append(f"  [+] {r.challenge_name} ({r.test_id}) via {r.tool_used}")

        tested_not_confirmed = [r for r in self.challenge_results if r.tested and not r.confirmed]
        if tested_not_confirmed:
            lines.append(f"\nTested but not confirmed ({len(tested_not_confirmed)}):")
            for r in tested_not_confirmed:
                lines.append(f"  [-] {r.challenge_name} ({r.test_id})")

        not_tested = [r for r in self.challenge_results if not r.tested]
        if not_tested:
            lines.append(f"\nNot tested ({len(not_tested)}):")
            for r in not_tested[:20]:
                lines.append(f"  [ ] {r.challenge_name} ({r.test_id})")
            if len(not_tested) > 20:
                lines.append(f"  ... and {len(not_tested) - 20} more")

        lines.append("=" * 60)
        return "\n".join(lines)


class TestExecutor(Protocol):
    def execute_test(self, test_id: str, target_url: str) -> Dict[str, Any]: ...


class DefaultTestExecutor:
    def execute_test(self, test_id: str, target_url: str) -> Dict[str, Any]:
        return {"success": False, "tool": "none", "error": "no executor configured"}


class JuiceShopBenchmarkRunner:
    def __init__(
        self,
        target_url: str,
        test_executor: Optional[Any] = None,
        mapper: Optional[JuiceShopChallengeMapper] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.test_executor = test_executor or DefaultTestExecutor()
        self.mapper = mapper or JuiceShopChallengeMapper()

    def run_benchmark(self) -> BenchmarkResult:
        mapping = self.mapper.map_challenges_to_tests()
        total = len(mapping)

        result = BenchmarkResult(expected=total)
        tested_test_ids: Dict[str, Dict[str, Any]] = {}

        for challenge_name, test_id in mapping.items():
            cr = ChallengeResult(challenge_name=challenge_name, test_id=test_id)

            if test_id not in tested_test_ids:
                try:
                    exec_result = self.test_executor.execute_test(test_id, self.target_url)
                    tested_test_ids[test_id] = exec_result
                except Exception as e:
                    logger.error(f"Test execution failed for {test_id}: {e}")
                    tested_test_ids[test_id] = {"success": False, "tool": "none", "error": str(e)}

            exec_result = tested_test_ids[test_id]
            cr.tested = True
            cr.tool_used = exec_result.get("tool", "")
            cr.error = exec_result.get("error", "")

            if exec_result.get("success", False):
                cr.confirmed = True

            result.challenge_results.append(cr)

        result.tested = sum(1 for r in result.challenge_results if r.tested)
        result.confirmed = sum(1 for r in result.challenge_results if r.confirmed)
        result.coverage = (result.confirmed / result.expected * 100.0) if result.expected > 0 else 0.0

        logger.info(f"BENCHMARK complete expected={result.expected} tested={result.tested} confirmed={result.confirmed} coverage={result.coverage:.1f}%")
        return result

    def generate_report(self) -> str:
        result = self.run_benchmark()
        return result.report()

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    
    if len(sys.argv) < 2:
        print("Usage: python -m core.benchmarking.benchmark_runner <target_url>")
        sys.exit(1)
        
    target_url = sys.argv[1]
    print(f"Starting Juice Shop Benchmark against {target_url}...\n")
    
    # Normally you would inject your real TestExecutor (like the CentralBrain or Pipeline)
    # Using DefaultTestExecutor here will just simulate the process and fail everything
    runner = JuiceShopBenchmarkRunner(target_url=target_url)
    report = runner.generate_report()
    
    print("\n" + report)
