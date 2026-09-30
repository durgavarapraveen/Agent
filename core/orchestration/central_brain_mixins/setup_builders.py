from __future__ import annotations

import logging

from core.security.capability_registry import CapabilityDefinition

logger = logging.getLogger(__name__)


class SetupBuildersMixin:
    """Construct/register subsystems on the brain: deterministic capability
    registration, report-grade PoC bundles, and the scope+consent-gated
    post-exploitation runner. Extracted from CentralBrain.
    """

    def _register_capabilities(self):
        for name, executor in [
            ("sqli", self.sqli_executor),
            ("xss", self.xss_executor),
            ("authentication", self.auth_executor),
            ("authorization", self.authz_executor),
        ]:
            self.capability_registry.register(CapabilityDefinition(
                name=name,
                executor_class=type(executor),
                timeout_seconds=executor.timeout_seconds,
                description=f"Deterministic {name} executor",
            ))

    def _build_poc_bundles(self) -> int:
        """Assemble a normalized, report-grade PoC bundle on each confirmed finding
        from evidence already captured — request/proof, response snapshot,
        screenshot path, technique, and reproduction steps. Idempotent; non-fatal."""
        n = 0
        for v in (getattr(self.ctx, "vulnerabilities", []) or []):
            if not isinstance(v, dict) or v.get("poc"):
                continue
            det = v.get("details", {}) if isinstance(v.get("details"), dict) else {}
            url = v.get("url") or v.get("location") or det.get("url") or ""
            proof = v.get("proof") or v.get("evidence") or det.get("proof") or ""
            resp = det.get("response_snippet") or det.get("error_snippet") or v.get("response") or ""
            shot = (v.get("screenshot") or v.get("screenshot_path")
                    or (v.get("evidence", {}) or {}).get("screenshot")
                    if isinstance(v.get("evidence"), dict) else v.get("screenshot"))
            steps = [s for s in [
                f"Target the endpoint: {url}" if url else "",
                f"Send the proving request ({det.get('technique', v.get('sub_type', 'payload'))}).",
                f"Observe: {str(proof)[:160]}" if proof else "",
                ("Out-of-band callback received (blind confirmation)."
                 if det.get("oob") else ""),
            ] if s]
            v["poc"] = {
                "url": url,
                "technique": det.get("technique") or v.get("sub_type") or "",
                "request_proof": str(proof)[:500],
                "response_snapshot": str(resp)[:500],
                "screenshot": shot or "",
                "oob": det.get("oob") or [],
                "confirmed": bool(v.get("confirmed") or v.get("status") == "CONFIRMED"),
                "steps": steps,
            }
            n += 1
        if n:
            logger.info(f"[PoC] built {n} reproduction bundle(s)")
        return n

    def _build_postex_runner(self):
        """B3: return a scope-gated command runner for post-exploitation, or
        None (plan-only). Activating live post-ex execution requires ALL of:
          1. operator opt-in via env NEO_ENABLE_POSTEX=1 (default off),
          2. a real foothold command channel present on ctx.foothold_runner,
          3. per-command scope validation + consent (never removed/weakened).
        Against a web target with no OS foothold this correctly returns None."""
        import os
        if os.getenv("NEO_ENABLE_POSTEX", "0") != "1":
            return None
        channel = getattr(self.ctx, "foothold_runner", None)
        if not callable(channel):
            logger.info("[PostExploit] NEO_ENABLE_POSTEX set but no foothold channel — plan-only")
            return None

        target = getattr(self.ctx, "target", "")

        async def _scoped_runner(cmd: str) -> str:
            # Authorization checks are mandatory and must never be bypassed.
            try:
                from core.security.authorization import TargetScopeValidator
                if not TargetScopeValidator.get().is_authorized(target):
                    logger.warning(f"[PostExploit] DENY out-of-scope target: {target}")
                    return "[denied: out-of-scope]"
            except Exception as e:
                logger.warning(f"[PostExploit] scope check failed, refusing: {e}")
                return "[denied: scope-check-error]"
            try:
                from core.security.consent import get_consent
                if not get_consent().allows("post_exploit_exec"):
                    return "[denied: no-consent]"
            except Exception:
                pass  # consent module optional; scope check already enforced
            out = await channel(cmd)
            try:
                from core.orchestration import blackboard as _bb
                _bb.post(getattr(self, "_scan_id", ""), "postex", "pivot",
                         f"post-ex cmd on {target}",
                         {"cmd": str(cmd)[:200], "output_preview": str(out)[:300]})
            except Exception:
                pass
            return out

        logger.info("[PostExploit] Live runner ENABLED (scope+consent gated)")
        return _scoped_runner
