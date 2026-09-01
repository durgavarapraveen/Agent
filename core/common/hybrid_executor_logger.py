import os
import json
from datetime import datetime, timezone
from typing import Dict

class HybridExecutorLogger:
    """
    Logger to track which execution path (A or B) was used for each tool.
    """
    
    def __init__(self, log_dir="data/logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, "hybrid_execution.log")

    def log_task_execution(self, task_id: str, approach: str, capability: str, 
                           tool_id: str, success: bool, duration_sec: float):
        """Create JSON entry and append as single line to log file"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "task_id": task_id,
            "approach": approach,
            "capability": capability,
            "tool_id": tool_id,
            "success": success,
            "duration_sec": duration_sec
        }
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def get_execution_summary(self) -> Dict[str, int]:
        """Read log file and count approach A vs B executions"""
        summary = {"A": 0, "B": 0, "total": 0}
        
        if not os.path.exists(self.log_file):
            return summary
            
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    approach = data.get("approach")
                    if approach == "A":
                        summary["A"] += 1
                    elif approach == "B":
                        summary["B"] += 1
                    summary["total"] += 1
                except json.JSONDecodeError:
                    continue
                    
        return summary

    def print_summary(self):
        """Print formatted table of execution distribution"""
        summary = self.get_execution_summary()
        count_a = summary["A"]
        count_b = summary["B"]
        total = summary["total"]
        
        pct_a = (count_a / total * 100) if total > 0 else 0
        pct_b = (count_b / total * 100) if total > 0 else 0
        
        print(f"Approach A (DeepSeek): {count_a} executions")
        print(f"Approach B (Claude): {count_b} executions")
        print(f"Total: {total} executions")
        
        # Determine whether to print floats or integers for clean output
        fmt_a = f"{pct_a:.1f}".rstrip('0').rstrip('.') if pct_a % 1 == 0 else f"{pct_a:.1f}"
        fmt_b = f"{pct_b:.1f}".rstrip('0').rstrip('.') if pct_b % 1 == 0 else f"{pct_b:.1f}"
        
        print(f"Distribution: {fmt_a}% A, {fmt_b}% B")
