#!/usr/bin/env python
"""Debt ratchet: fail CI if tracked lint debt grows above the committed baseline.

Burn debt down in reviewed PRs, then run `--update` to lower the baseline.
New code may never add BLE001 (blind except) or B904 (raise-without-from).
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "lint_baseline.json"
RULES = ["BLE001", "B904"]


def count(rule: str) -> int:
    out = subprocess.run(
        ["ruff", "check", ".", "--select", rule, "--output-format", "concise"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    return sum(1 for line in out.splitlines() if f"{rule}" in line and ".py:" in line)


def main() -> int:
    current = {r: count(r) for r in RULES}
    if "--update" in sys.argv:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n")
        print("baseline updated:", current)
        return 0
    base = json.loads(BASELINE.read_text())
    failed = False
    for r in RULES:
        allowed, now = base.get(r, 0), current[r]
        flag = "OK " if now <= allowed else "GREW"
        if now > allowed:
            failed = True
        print(f"[{flag}] {r}: {now} (baseline {allowed})")
    if failed:
        print("\nNew tracked-debt introduced. Fix the finding or burn debt and run --update.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
