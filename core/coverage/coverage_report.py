from core.coverage.coverage_engine import CoverageEngine
from core.domain.coverage import TestState

class CoverageReportGenerator:
    def __init__(self, engine: CoverageEngine):
        self.engine = engine
        
    def generate_markdown(self) -> str:
        state = self.engine.state
        stats = self.engine.get_coverage_status()
        pct = self.engine.calculate_coverage_pct()
        
        lines = []
        lines.append("# Security Coverage Report")
        lines.append(f"**Overall Coverage:** {pct:.2f}%")
        lines.append("")
        
        lines.append("## Metrics")
        for k, v in stats.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")
        
        # Categorize
        confirmed = []
        blocked = []
        gaps = []
        
        for test_id, run_state in state.coverage_map.items():
            test_def = self.engine.catalog.get_test(test_id)
            desc = test_def.description if test_def else "Unknown test"
            
            if run_state.status == TestState.CONFIRMED:
                confirmed.append((test_id, desc))
            elif run_state.status == TestState.BLOCKED:
                blocked.append((test_id, run_state.failure_reason or "Unknown block reason"))
            elif run_state.status in {TestState.NOT_TESTED, TestState.INCONCLUSIVE, TestState.READY}:
                gaps.append((test_id, run_state.status.value))
                
        lines.append("## Confirmed Findings")
        if not confirmed:
            lines.append("*None*")
        for tid, desc in confirmed:
            lines.append(f"- **{tid}**: {desc}")
        lines.append("")
        
        lines.append("## Blocked Tests")
        if not blocked:
            lines.append("*None*")
        for tid, reason in blocked:
            lines.append(f"- **{tid}**: {reason}")
        lines.append("")
        
        lines.append("## Coverage Gaps")
        if not gaps:
            lines.append("*None*")
        for tid, status in gaps:
            lines.append(f"- **{tid}**: Currently `{status}`")
            
        return "\n".join(lines)
