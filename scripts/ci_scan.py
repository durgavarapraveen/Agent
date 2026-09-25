#!/usr/bin/env python3
"""Phase 3.2 — CI wrapper around the scanner, optimized for pipelines.

Non-interactive (no consent prompts), machine-readable output (SARIF + JSON),
and a severity gate that sets the process exit code so a pipeline can fail a PR
when findings exceed a threshold.

Two modes:
  * ``--findings results.json`` — gate an existing findings file (fast; used by
    the GitHub Action after the scan step, and by tests);
  * ``--target URL`` — invoke ``main.py`` non-interactively (``--auto-approve
    --sarif``) then gate its output.

Reuses ``core.reporting.sarif_export.SARIFExporter`` for SARIF generation.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEV_ORDER = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_gate(findings: List[Dict[str, Any]], fail_on: str = "high") -> Tuple[int, Dict[str, Any]]:
    """Return (exit_code, summary). exit_code is 1 if any finding's severity is
    at or above `fail_on`, else 0."""
    threshold = SEV_ORDER.get(str(fail_on).lower(), 3)
    counts = Counter(str(f.get("severity", "medium")).lower() for f in findings)
    max_rank = max((SEV_ORDER.get(s, 2) for s in counts), default=-1)
    over = sum(n for s, n in counts.items() if SEV_ORDER.get(s, 2) >= threshold)
    exit_code = 1 if over > 0 else 0
    max_sev = next((s for s, r in SEV_ORDER.items() if r == max_rank), "none") if max_rank >= 0 else "none"
    return exit_code, {
        "total": len(findings),
        "counts": dict(counts),
        "max_severity": max_sev,
        "fail_on": str(fail_on).lower(),
        "over_threshold": over,
        "gate": "FAIL" if exit_code else "PASS",
    }


def build_sarif(findings: List[Dict[str, Any]], target: str = "",
                output_path: str = "") -> Dict[str, Any]:
    from core.reporting.sarif_export import SARIFExporter
    return SARIFExporter().export(findings, target=target, output_path=output_path or None)


def load_findings(path: str) -> List[Dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        return []
    return data if isinstance(data, list) else []


def run_ci_scan(findings: List[Dict[str, Any]], *, target: str = "", fail_on: str = "high",
                sarif_out: str = "", json_out: str = "") -> Tuple[int, Dict[str, Any]]:
    exit_code, summary = severity_gate(findings, fail_on)
    if sarif_out:
        build_sarif(findings, target=target, output_path=sarif_out)
    if json_out:
        Path(json_out).write_text(json.dumps({"summary": summary, "findings": findings},
                                             indent=2), encoding="utf-8")
    return exit_code, summary


def _invoke_scan(args) -> List[Dict[str, Any]]:
    """Run main.py non-interactively and return its findings (best-effort)."""
    scan_id = args.scan_id or "ci_scan"
    cmd = [sys.executable, str(ROOT / "main.py"), "--target", args.target,
           "--tier", args.tier, "--auto-approve", "--sarif", "--scan-id", scan_id]
    if args.phases:
        cmd += ["--phases", args.phases]
    print(f"[ci_scan] running: {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=str(ROOT), check=False)
    # main.py --sarif writes a results file; look for a findings JSON to gate.
    for candidate in (f"reports/{scan_id}/findings.json", f"data/scans/{scan_id}/findings.json"):
        p = ROOT / candidate
        if p.exists():
            return load_findings(str(p))
    print("[ci_scan] WARNING: no findings file found after scan", flush=True)
    return []


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AntiGravity CI scan wrapper")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="Path to an existing findings JSON to gate")
    src.add_argument("--target", help="Target to scan via main.py")
    parser.add_argument("--tier", default="POC")
    parser.add_argument("--phases", default="")
    parser.add_argument("--scan-id", default="")
    parser.add_argument("--fail-on", default="high",
                        choices=["info", "low", "medium", "high", "critical"])
    parser.add_argument("--sarif-out", default="antigravity.sarif")
    parser.add_argument("--json-out", default="antigravity-findings.json")
    args = parser.parse_args(argv)

    findings = load_findings(args.findings) if args.findings else _invoke_scan(args)
    exit_code, summary = run_ci_scan(
        findings, target=args.target or "", fail_on=args.fail_on,
        sarif_out=args.sarif_out, json_out=args.json_out)
    print(f"[ci_scan] {summary['gate']}: {summary['total']} findings "
          f"(max={summary['max_severity']}, fail-on={summary['fail_on']}, "
          f"over-threshold={summary['over_threshold']})", flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
