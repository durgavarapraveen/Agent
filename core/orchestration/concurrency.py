"""Shared concurrency caps for fanning out independent scan work.

Two distinct pools because they contend on different resources:
  - probe_concurrency(): HTTP-bound probes (NetworkBroker). Safe to run several
    at once; still bounded so we don't trip the target's WAF/rate-limit.
  - kali_concurrency(): tools that shell into the SINGLE shared Kali container
    (sqlmap/dalfox/nuclei/...). Kept small — concurrent `docker exec` into one
    container contends on CPU and racy apt installs.

Both read env overrides so an operator can tune per-run. An optional
`health` object (anything exposing a `.concurrency` int, e.g.
TargetHealthManager) narrows the cap when the target is degraded/throttled.
"""
from __future__ import annotations

import os


def _cap(env: str, default: int, health=None) -> int:
    try:
        cap = int(os.getenv(env, str(default)))
    except (TypeError, ValueError):
        cap = default
    cap = max(1, cap)
    try:
        if health is not None and hasattr(health, "concurrency"):
            hc = int(health.concurrency)
            if hc >= 1:
                cap = min(cap, hc)
    except Exception:
        pass
    return cap


def probe_concurrency(health=None) -> int:
    """Bound for HTTP-bound probe fan-out. Default 4."""
    return _cap("PROBE_CONCURRENCY", 4, health)


def kali_concurrency(health=None) -> int:
    """Bound for Kali-container tool fan-out. Default 2 (shared container)."""
    return _cap("KALI_CONCURRENCY", 2, health)
