#!/usr/bin/env python
"""Generate a versioned benchmark corpus from a live target and (optionally)
score a scan's findings against it. Benchmark-agnostic — works for any target
that exposes a challenge API, and falls back to a static corpus otherwise.

Examples:
  # Discover + save the corpus for a suite from the live target
  python scripts/generate_benchmark_corpus.py --target https://preview.owasp-juice.shop --suite juice-shop

  # Also score an existing scan's findings against it (persists + blackboard)
  python scripts/generate_benchmark_corpus.py --target https://x --suite juice-shop --score-scan <scan_id>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def _load_findings(scan_id: str):
    from core.database.pg_store import DatabaseManager
    rows = []
    try:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT type, location, status, confidence_score FROM vulnerabilities WHERE scan_id=%s",
                    (scan_id,))
                for t, loc, st, conf in (cur.fetchall() or []):
                    rows.append({"type": t, "location": loc, "status": st,
                                 "confirmed": str(st or "").upper() == "CONFIRMED",
                                 "confidence": float(conf or 0)})
    except Exception as e:
        print(f"[warn] could not load findings for {scan_id}: {e}", file=sys.stderr)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/score a generic benchmark corpus")
    ap.add_argument("--target", required=True, help="Target base URL (challenge API is discovered on it)")
    ap.add_argument("--suite", required=True, help="Benchmark suite name (e.g. juice-shop, dvwa, my-app)")
    ap.add_argument("--version", default="", help="Corpus version (default: today YYYYMMDD)")
    ap.add_argument("--score-scan", default="", help="Scan id whose findings to score against the corpus")
    args = ap.parse_args()

    from core.benchmark.runner import generate_corpus, score_corpus

    version = args.version or datetime.now(timezone.utc).strftime("%Y%m%d")
    corpus = generate_corpus(args.target, args.suite, version, scan_id=args.score_scan)
    print(f"corpus: {corpus.suite}/{corpus.version} — {len(corpus.challenges)} challenge(s) → {corpus.path()}")
    if not corpus.challenges:
        print("no challenges discovered (no live challenge API + no static corpus).")
        return 0

    if args.score_scan:
        findings = _load_findings(args.score_scan)
        summary = score_corpus(args.score_scan, corpus, findings, ctx=None)
        print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
