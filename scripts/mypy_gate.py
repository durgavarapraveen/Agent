#!/usr/bin/env python
"""Type-gate ratchet: run mypy (lenient, mypy.ini) on tracked packages and fail
if any package's error count grows above its committed baseline.

Burn errors down, then `--update` to lower the baseline. Add packages to
mypy_baseline.json to extend coverage.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "mypy_baseline.json"


def count(pkg: str) -> int:
    out = subprocess.run(
        ["mypy", pkg, "--config-file", str(ROOT / "mypy.ini"), "--no-error-summary"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    return sum(1 for line in out.splitlines() if ": error:" in line)


def main() -> int:
    base = json.loads(BASELINE.read_text())
    current = {pkg: count(pkg) for pkg in base}
    if "--update" in sys.argv:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print("baseline updated:", current)
        return 0
    failed = False
    for pkg, allowed in sorted(base.items()):
        now = current[pkg]
        if now > allowed:
            failed = True
        print(f"[{'OK ' if now <= allowed else 'GREW'}] {pkg}: {now} (baseline {allowed})")
    if failed:
        print("\nNew type errors introduced. Fix them or burn debt and run --update.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
