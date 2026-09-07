"""CyberGym benchmark harness (Phase 2.6).

CyberGym (sunblaze-ucb, https://github.com/sunblaze-ucb/CyberGym) is a
task-based cybersecurity benchmark used internally at OpenAI according to
the July 2026 HF incident report. Public tasks are shipped as Docker
containers with a well-defined goal (recover a flag, achieve RCE, etc.).

This harness:
  1. Clones the public CyberGym repo (once) to `~/.cache/cybergym`,
  2. Enumerates each task's `task.yaml`,
  3. Spins the task's container,
  4. Points our AntiGravity agent at the container's exposed port,
  5. Compares the ctx.vulnerabilities against the task's expected
     grade rubric,
  6. Emits a per-task pass/fail + a top-line score.

Run:
    python -m tests.benchmarks.cybergym_runner --tasks web-basic --limit 5

Skip flags:
  --local-only : only tasks that don't need external network access
  --dry-run    : list tasks without executing them
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cybergym")
_CACHE = Path(os.environ.get("CYBERGYM_CACHE",
                             str(Path.home() / ".cache" / "cybergym")))
_REPO = "https://github.com/sunblaze-ucb/CyberGym.git"


def _ensure_repo() -> Optional[Path]:
    """Clone the CyberGym repo if not already present."""
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    if (_CACHE / ".git").exists():
        return _CACHE
    r = subprocess.run(["git", "clone", "--depth", "1", _REPO, str(_CACHE)],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        logger.error(f"[CyberGym] clone failed: {r.stderr[:400]}")
        return None
    return _CACHE


def _iter_tasks(root: Path, task_glob: str) -> List[Path]:
    return sorted(root.glob(f"tasks/{task_glob}*/task.yaml"))


def _load_task(task_yaml: Path) -> Dict[str, Any]:
    try:
        import yaml
        return yaml.safe_load(task_yaml.read_text(encoding="utf-8")) or {}
    except Exception as e:
        logger.debug(f"[CyberGym] cannot parse {task_yaml}: {e}")
        return {}


def _launch_target(task_dir: Path, task: Dict[str, Any]) -> Optional[str]:
    """Bring up the task's docker-compose stack. Returns the target base
    URL if the task exposes an HTTP service; else None."""
    compose = task_dir / "docker-compose.yml"
    if not compose.exists() or not shutil.which("docker"):
        return None
    port = task.get("expose_port") or 8080
    r = subprocess.run(
        ["docker", "compose", "-f", str(compose), "up", "-d"],
        capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        logger.error(f"[CyberGym] compose up failed: {r.stderr[:400]}")
        return None
    time.sleep(3)   # give the container a moment to come up
    return f"http://localhost:{port}"


def _tear_down(task_dir: Path) -> None:
    compose = task_dir / "docker-compose.yml"
    if compose.exists() and shutil.which("docker"):
        subprocess.run(["docker", "compose", "-f", str(compose), "down", "-v"],
                       capture_output=True, timeout=60)


async def _run_agent(target: str, timeout_s: int) -> List[Dict[str, Any]]:
    """Call into main.py's `run_single` in-process — no subprocess."""
    from main import run_single
    try:
        await asyncio.wait_for(
            run_single(target, auth=None, tier="benchmark"),
            timeout=timeout_s)
    except asyncio.TimeoutError:
        logger.warning(f"[CyberGym] agent timed out on {target}")
    # Read vulnerabilities out of the DB for this scan.
    try:
        from core.database.pg_store import VulnRepo
        return VulnRepo.list_latest(target=target, limit=500)
    except Exception:
        return []


def _grade(task: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Very simple rubric: any finding of type matching task['expected_type']
    or containing task['expected_marker'] scores 1; else 0."""
    expected_type = task.get("expected_type")
    expected_marker = task.get("expected_marker")
    hit = False
    for f in findings or []:
        if expected_type and str(f.get("type", "")).lower() == expected_type.lower():
            hit = True
            break
        if expected_marker:
            blob = json.dumps(f, default=str).lower()
            if expected_marker.lower() in blob:
                hit = True
                break
    return {"pass": hit, "expected_type": expected_type,
            "expected_marker": expected_marker,
            "findings_count": len(findings or [])}


async def _run_one(task_yaml: Path, agent_timeout_s: int,
                   dry_run: bool) -> Dict[str, Any]:
    task_dir = task_yaml.parent
    task = _load_task(task_yaml)
    name = task_dir.name
    if dry_run:
        return {"task": name, "dry_run": True, "task_type": task.get("type")}
    target = _launch_target(task_dir, task)
    if not target:
        return {"task": name, "skipped": "no_target"}
    try:
        findings = await _run_agent(target, agent_timeout_s)
        grade = _grade(task, findings)
        return {"task": name, "target": target, **grade}
    finally:
        _tear_down(task_dir)


async def main_async(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tasks", default="web", help="Task glob prefix (e.g. web, ctf, rce)")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--per-task-timeout", type=int, default=900)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    repo = _ensure_repo()
    if repo is None:
        print("[CyberGym] repo unavailable — install git or check network")
        return 2
    tasks = _iter_tasks(repo, args.tasks)[: args.limit]
    if not tasks:
        print(f"[CyberGym] no tasks matched {args.tasks!r}")
        return 3
    results = []
    for t in tasks:
        r = await _run_one(t, args.per_task_timeout, args.dry_run)
        results.append(r)
        print(json.dumps(r, default=str))
    passed = sum(1 for r in results if r.get("pass"))
    print(f"\n=== SUMMARY: {passed}/{len(results)} tasks passed ===")
    return 0 if passed == len(results) else 1


def main(argv: Optional[List[str]] = None) -> int:
    return asyncio.run(main_async(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
