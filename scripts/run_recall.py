#!/usr/bin/env python
"""Run the agent against a known-vulnerable target and print recall/precision.

Usage:
    RECALL_TARGET=http://localhost:3000 CORPUS=juice_shop python scripts/run_recall.py
    RECALL_TARGET=http://localhost/dvwa CORPUS=dvwa python scripts/run_recall.py

Requires the target to be running and IN SCOPE (set ALLOW_PRIVATE_TARGETS=true +
scope for localhost labs). Exits non-zero if recall < RECALL_MIN (default 0.0, so
it only gates when you set a threshold). Writes recall_report.json.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validation.recall_harness import score, juice_shop_catalog, dvwa_catalog


async def _scan(target: str) -> list:
    """Best-effort scan: crawl (if available) → classify → dispatch → collect."""
    from core.memory.shared_context import SharedContextV2 as SharedContext
    ctx = SharedContext(target=target)
    # 1. populate surfaces via the browser crawler when present, else a light fetch
    try:
        from core.browser.crawler import crawl_into_context
        await crawl_into_context(ctx, target)
    except Exception as e:
        print(f"[recall] crawler unavailable/failed ({e}); seeding single endpoint")
        try:
            ctx.add_captured_request({"url": target, "method": "GET", "headers": {}})
        except Exception:
            pass
    # 2. run the surface-driven dispatcher (the primary injection path)
    from core.orchestration.dispatcher import run_dispatcher
    await run_dispatcher(ctx)
    return list(getattr(ctx, "vulnerabilities", []) or [])


def main() -> int:
    target = os.getenv("RECALL_TARGET")
    if not target:
        print("RECALL_TARGET not set — nothing to scan. (This is expected in unit CI.)")
        return 0
    corpus = os.getenv("CORPUS", "juice_shop").lower()
    catalog = dvwa_catalog() if corpus == "dvwa" else juice_shop_catalog()

    findings = asyncio.run(_scan(target))
    report = score(findings, catalog, confirmed_only=False)
    out = report.to_dict()
    with open("recall_report.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(json.dumps({k: out[k] for k in ("total_known", "detected", "recall", "precision")}, indent=2))
    print(f"MISSES ({len(out['miss_list'])}):")
    for m in out["miss_list"][:60]:
        print(f"  - [{m['class']}] {m['id']} {m['title']}")

    threshold = float(os.getenv("RECALL_MIN", "0"))
    if report.recall < threshold:
        print(f"FAIL: recall {report.recall:.2%} < RECALL_MIN {threshold:.2%}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
