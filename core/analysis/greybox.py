"""Grey-box orchestrator = SAST (static) + DAST (on the running app) + correlate.

The strongest single-codebase assessment:
  1. SAST — Semgrep over the source (find potential issues + locations).
  2. Dynamic — if the repo is containerized, build & run it, then point the
     surface-driven DAST engine at the live app (find what's exploitable at runtime).
  3. Correlate — same vuln class + overlapping location in BOTH ⇒ CONFIRMED;
     SAST-only ⇒ "potential, needs validation"; DAST-only ⇒ "confirmed at runtime".

Falls back to SAST-only (with a clear reason) when the app can't be run.
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections import Counter
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


async def run_greybox(source_path: str = "", source_repo: str = "",
                      dynamic: bool = True, dast_budget: int = 0,
                      on_step=None) -> Dict[str, Any]:
    from core.analysis.sast_bridge import SastBridge, correlate_sast_dast

    def _step(msg: str, status: str = "running"):
        """Best-effort progress emit — never breaks the analysis."""
        logger.info("[greybox] %s", msg)
        if on_step:
            try:
                on_step(msg, status)
            except Exception:
                pass

    bridge = SastBridge()
    path = source_path
    cloned_dir = ""   # set only when WE cloned — deleted in the finally below
    if source_repo and not path:
        _step(f"Cloning repository {source_repo} …")
        # Offload the blocking git clone to a thread so the event loop (and the
        # progress-poll endpoint) stay responsive while it runs.
        path = (await asyncio.to_thread(bridge.clone_repo, source_repo)) or ""
        cloned_dir = path
        _step("Repository cloned." if path else "Clone failed.",
              "done" if path else "error")

    try:
        # ── 1. SAST ──────────────────────────────────────────────────────
        sast: List[Dict[str, Any]] = []
        if path and os.path.isdir(path):
            _step("Running SAST (Semgrep security rules) …")
            sast = await asyncio.to_thread(bridge.run_semgrep, path)
            _step(f"SAST complete — {len(sast)} finding(s).", "done")
        elif not path:
            logger.warning("greybox: no source path (clone failed?)")
            _step("No source path — clone failed; skipping SAST.", "error")

        # ── 2. Dynamic (build & run → DAST) ───────────────────────────────
        dast: List[Dict[str, Any]] = []
        dynamic_ran = False
        dynamic_reason = "disabled" if not dynamic else ""
        base_url = ""
        if dynamic and path and os.path.isdir(path):
            _step("Building & running the app (Docker), then DAST …")
            # Hard cap the dynamic phase so a slow/hanging Docker build (common on
            # large multi-service apps) can't stall the whole run forever — which
            # would mean the SAST results never get persisted. On timeout we keep
            # the SAST findings and mark DAST skipped.
            from core.common.settings import settings
            budget_s = settings.greybox_dynamic_timeout
            try:
                dast, dynamic_ran, dynamic_reason, base_url = await asyncio.wait_for(
                    _run_dynamic(path, dast_budget, sast), timeout=budget_s)
            except asyncio.TimeoutError:
                dast, dynamic_ran, base_url = [], False, ""
                dynamic_reason = f"timed out after {budget_s}s (build/run too slow)"
                logger.warning("[greybox] dynamic phase timed out after %ss", budget_s)
                # Best-effort: tear down anything the runner may have started.
                try:
                    from core.analysis.app_runner import DockerAppRunner
                    DockerAppRunner().teardown()
                except Exception:
                    pass
            _step(f"Dynamic scan {'complete' if dynamic_ran else 'skipped'} "
                  f"— {len(dast)} finding(s)"
                  + (f" ({dynamic_reason})" if not dynamic_ran and dynamic_reason else "") + ".",
                  "done" if dynamic_ran else "error")

        # ── 3. Correlate ──────────────────────────────────────────────────
        _step("Correlating SAST ↔ DAST findings …")
        correlation = correlate_sast_dast(sast, dast)
        _step("Analysis complete.", "done")

        return {
            "source_repo": source_repo,
            "source_path": source_path,
            "sast_count": len(sast),
            "dast_count": len(dast),
            "dynamic_ran": dynamic_ran,
            "dynamic_reason": dynamic_reason,
            "dynamic_url": base_url,
            "sast": sast,
            "dast": dast,
            "by_class": dict(Counter(f.get("vuln_class", f.get("type", "generic")) for f in sast)),
            "correlation": {
                "confirmed": correlation["confirmed"],
                "sast_only": correlation["sast_only"],
                "dast_only": correlation["dast_only"],
                "counts": {
                    "confirmed": len(correlation["confirmed"]),
                    "sast_only": len(correlation["sast_only"]),
                    "dast_only": len(correlation["dast_only"]),
                },
            },
        }
    finally:
        # Delete the cloned source tree once analysis is done — findings are
        # already persisted to Postgres; the code checkout is not kept on disk.
        if cloned_dir and os.path.isdir(cloned_dir):
            try:
                import shutil
                await asyncio.to_thread(shutil.rmtree, cloned_dir, True)  # ignore_errors=True
                logger.info("[greybox] removed cloned source tree %s", cloned_dir)
            except Exception as e:
                logger.warning("[greybox] clone cleanup failed (non-fatal): %s", e)


async def _run_dynamic(path: str, dast_budget: int, sast: List[Dict[str, Any]] | None = None):
    """Build+run the app, DAST it, tear down. Returns (findings, ran, reason, url)."""
    from core.analysis.app_runner import DockerAppRunner
    runner = DockerAppRunner()
    app = runner.start(path)
    if not app.ok:
        return [], False, app.reason, ""
    try:
        host = urlparse(app.base_url).hostname or "localhost"
        # Authorize the built app's URL for THIS run only (our own container).
        prev_allow = os.environ.get("ALLOW_PRIVATE_TARGETS")
        os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
        try:
            from core.security.authorization import TargetScopeValidator
            TargetScopeValidator.set(TargetScopeValidator(
                [host, "localhost", "127.0.0.1"], allow_wildcard=False))
        except Exception:
            pass

        findings = await _dast_scan(app.base_url, dast_budget, path, sast)

        if prev_allow is None:
            os.environ.pop("ALLOW_PRIVATE_TARGETS", None)
        else:
            os.environ["ALLOW_PRIVATE_TARGETS"] = prev_allow
        return findings, True, "", app.base_url
    except Exception as e:
        logger.warning("greybox dynamic scan failed: %s", e)
        return [], False, f"dynamic scan error: {e}", app.base_url
    finally:
        runner.teardown()


async def _dast_scan(base_url: str, budget: int, source_path: str = "",
                     sast: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """Surface-driven DAST against the running app, reusing the scan engine
    (crawl → classify → dispatch → oracle). Bounded, self-contained.

    Beyond the crawler, SAST-derived routes/params are seeded as candidate
    injection surfaces so DAST reaches endpoints that have no inbound link."""
    from core.memory.shared_context import SharedContextV2 as SharedContext
    from core.orchestration.dispatcher import run_dispatcher
    ctx = SharedContext(target=base_url)
    try:
        from core.browser.crawler import crawl_into_context
        await crawl_into_context(ctx, base_url)
    except Exception as e:
        logger.debug("greybox crawl failed (%s); seeding single endpoint", e)
        try:
            ctx.add_captured_request({"url": base_url, "method": "GET", "headers": {}})
        except Exception:
            pass

    # SAST→DAST seeding: turn declared routes + touched params into surfaces.
    if source_path:
        try:
            from core.analysis.endpoint_seeder import seed_requests_from_source
            for req in seed_requests_from_source(source_path, base_url, sast):
                ctx.add_captured_request(req)
        except Exception as e:
            logger.debug("greybox endpoint seeding failed (%s)", e)

    if budget:
        os.environ.setdefault("DISPATCH_BUDGET", str(budget))
    await run_dispatcher(ctx)
    return list(getattr(ctx, "vulnerabilities", []) or [])
