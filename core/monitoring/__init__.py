"""
Continuous Attack Surface Monitoring (Feature #3).

Turns a one-shot pentest into a repeatable monitor: each run captures a
normalized snapshot of the target's assets and findings, diffs it against the
previous snapshot, and emits only the deltas (new subdomains/ports/endpoints,
technology changes, new vs. resolved findings, header regressions).
"""

from core.monitoring.asm_monitor import ASMMonitor, ASMDelta

__all__ = ["ASMMonitor", "ASMDelta"]
