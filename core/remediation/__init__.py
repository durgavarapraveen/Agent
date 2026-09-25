"""Remediation planning: turn confirmed findings into concrete, actionable fixes.

The platform's job is not only to FIND vulnerabilities but to help FIX them
(project brief). This package produces a per-finding `remediation_plan`
(root cause, concrete fix, optional code patch, verification steps, references)
so an operator can remediate before a real attacker exploits the issue.

Non-destructive: it NEVER modifies the target or applies patches. It produces
reviewable guidance only.
"""
from core.remediation.fix_planner import FixPlanner, get_fix_planner

__all__ = ["FixPlanner", "get_fix_planner"]
