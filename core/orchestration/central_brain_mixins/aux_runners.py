from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, List

logger = logging.getLogger(__name__)


class AuxRunnersMixin:
    """Auxiliary self-contained runners: adaptive agent spawning from recon,
    network-service vulnerability verification, and the dynamic-hypothesis
    cycle. Each adds findings to ctx; none drive phase transitions. Extracted
    from CentralBrain.
    """

    async def _adaptive_spawn_from_recon(self) -> None:
        """Hybrid pipeline hook: as soon as RECON knows the attack surface, launch
        specialist teams for the highest-value discovered signals NOW (concurrently,
        ahead of the ACTIVE_SCANNING sweep) instead of waiting. Bounded by
        ADAPTIVE_SPAWN_MAX (default 6) and deduped; the sweep skips what ran here."""
        try:
            from core.orchestration.family_scheduler import (
                family_for_signal, spawn_family_team, classify_family_jev)
            cap = int(os.getenv("ADAPTIVE_SPAWN_MAX", "6"))
            if self._adaptive_spawns >= cap:
                return
            # Collect endpoint/surface signals (dicts or strings) discovered in recon.
            eps = getattr(self.ctx, "endpoints", None)
            signals: List[str] = []
            if isinstance(eps, dict):
                for v in eps.values():
                    signals.append(v.get("url", "") if isinstance(v, dict) else str(v))
            elif isinstance(eps, (list, tuple, set)):
                for v in eps:
                    signals.append(v.get("url", "") if isinstance(v, dict) else str(v))

            # First relevant, not-yet-spawned family per signal → one team each,
            # capped. Launch concurrently; recon/next phase continues meanwhile.
            from collections import OrderedDict
            picks: "OrderedDict[Any, str]" = OrderedDict()
            for sig in signals:
                fam = family_for_signal(sig)
                if fam is None:  # opt-in Jev routing recovers missed signals
                    fam = await classify_family_jev(
                        sig, scan_id=getattr(self, "_scan_id", ""))
                if fam is None or fam in self._families_spawned or fam in picks:
                    continue
                picks[fam] = sig
                if self._adaptive_spawns + len(picks) >= cap:
                    break
            if not picks:
                return
            self._adaptive_spawns += len(picks)
            logger.info("[AdaptiveSpawn] recon surfaced %d specialist team(s): %s",
                        len(picks), [f.value for f in picks])
            await asyncio.gather(
                *[spawn_family_team(self, fam, reason=f"recon signal: {sig[:80]}")
                  for fam, sig in picks.items()],
                return_exceptions=True)
        except Exception as e:
            logger.debug(f"[AdaptiveSpawn] skipped: {e}")

    async def _run_network_verification(self):
        """Dispatch allow-listed Metasploit auxiliary scanners against open
        network services found during recon. Read-only (Level-A). Opt-in via
        NEO_ENABLE_MSF; each run is scope-validated and module-allow-listed in
        the adapter. Idempotent per scan."""
        from core.utils.scan_flags import enable_metasploit
        if not enable_metasploit():
            return
        if getattr(self, "_netverify_ran", False):
            return
        self._netverify_ran = True

        from core.tools.adapters.metasploit import _PORT_DEFAULT, _host
        ports = dict(getattr(self.ctx, "ports", {}) or {})
        host = _host(self.target or "")
        # Prefer a resolved IP when we have one (msf RHOSTS likes IPs).
        ips = list(getattr(self.ctx, "ips", []) or [])
        rhost = ips[0] if ips else host
        if not rhost:
            return

        jobs = []
        for p_str, _svc in ports.items():
            try:
                p = int(str(p_str).split("/")[0])
            except (TypeError, ValueError):
                continue
            mod = _PORT_DEFAULT.get(p)
            if mod:
                jobs.append((p, mod))
        if not jobs:
            logger.info("[MSF] no open services matched an aux-scanner module")
            return

        from core.security.authorization import AuthContext
        allowed_tools = list(self.tools.tools.keys()) if hasattr(self, "tools") and hasattr(self.tools, "tools") else []
        auth_context = AuthContext(allowed_tools=allowed_tools, has_elevated_privilege=True,
                                   target_profile=getattr(self, "target_profile", None))
        session_id = "session_netverify"

        logger.info(f"[MSF] network verification: {len(jobs)} module(s) on {rhost}")
        import re as _re
        for p, mod in jobs:
            try:
                params = {"target": rhost, "module": mod, "rport": p}
                result = await self.tool_invocation_engine.invoke_from_capability(
                    "network_vuln_verification", rhost, params, session_id, auth_context)
                out = str(getattr(result, "stdout", "") or "")
                # Aux scanners print a clear vulnerable signal; capture only that.
                if _re.search(r"\bVULNERABLE\b|appears? (?:to be )?vulnerable|is likely VULNERABLE", out, _re.I):
                    self.ctx.add_vulnerability({
                        "title": f"Metasploit {mod.split('/')[-1]} reports target VULNERABLE",
                        "type": "NETWORK_SERVICE",
                        "severity": "HIGH",
                        "location": f"{rhost}:{p}",
                        "target": rhost,
                        "details": f"msf module {mod} flagged {rhost}:{p} as vulnerable.",
                        "proof": out[-1500:],
                        "tool": "msf_scanner",
                    })
                    logger.info(f"[MSF] VULNERABLE: {mod} on {rhost}:{p}")
            except Exception as e:
                logger.debug(f"[MSF] {mod} on {rhost}:{p} failed: {e}")

        try:
            await self._flush_partial("msf_network_verification")
        except Exception:
            pass

    async def _run_dynamic_hypothesis_cycle(self, cycle_name: str = "first_order") -> None:
        """Pα: Run a dynamic hypothesis engine cycle to discover novel attack surfaces."""
        from core.intelligence.dynamic_hypothesis import DynamicHypothesisEngine
        # D-2: hand the LLM-driven Pα engine the SAME routed, cost-logged harness
        # the rest of the brain uses (it would otherwise self-fetch a separate
        # client, escaping role-routing + per-scan cost accounting).
        engine = DynamicHypothesisEngine(ctx=self.ctx, llm_client=getattr(self, "llm", None))
        findings = await engine.run_cycle(cycle_name=cycle_name)
        for f in findings:
            self.ctx.add_vulnerability(f)
        stats = engine.stats()
        logger.info(f"[Pα] {cycle_name}: tested={stats['hypotheses_tested']}, "
                    f"confirmed={stats['hypotheses_confirmed']}, findings={stats['findings']}")
        self._log_activity("pa_engine", f"Pα {cycle_name}: {stats['findings']} findings from "
                           f"{stats['hypotheses_tested']} hypotheses", tool="dynamic_hypothesis")
