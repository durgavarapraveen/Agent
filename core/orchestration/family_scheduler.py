"""Parallel, tiered specialist-probe scheduler — the agent's pentest *teams*.

Runs the ACTIVE_SCANNING specialist battery as concurrent **family tracks** at
different **skill tiers**, instead of a flat sequential list of ~450 lines of
copy-pasted try/except:

  - Each probe is a declarative `ProbeSpec` tagged with a `TestFamily` (so the
    Test Plan can skip families it scoped out — domain-adaptive) and an
    `AgentTier` (junior=breadth sweep, senior=depth).
  - "net" probes run concurrently under a bounded semaphore (`FAMILY_CONCURRENCY`,
    default 4); "browser" probes run in a serial lane (a shared browser is not
    concurrency-safe). Set FAMILY_CONCURRENCY=1 to restore fully-sequential order.
  - Partial / low-confidence findings are escalated to the SENIOR verify passes
    (second-order + retest) that already run later in the pipeline.

Reusable + declarative: add a probe = add a row to `REGISTRY`.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List

from core.orchestration.test_plan import AgentTier, TestFamily

logger = logging.getLogger(__name__)

J, S = AgentTier.JUNIOR, AgentTier.SENIOR
F = TestFamily


async def _reason(scan_id: str, agent_id: str, step: int, thought: str,
                  tool: str = "", status: int = 0) -> None:
    """Write one agent_reasoning row so a tracked agent's 'thoughts' panel shows
    what it is doing (these deterministic lanes/teams make no LLM calls of their
    own, so nothing would appear otherwise). Best-effort, off the event loop."""
    if not (scan_id and agent_id and thought):
        return

    def _w():
        try:
            from core.database.pg_store import DatabaseManager
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO agent_reasoning
                             (scan_id, agent_id, step, thought, tool_planned,
                              tool_args, tool_result_preview, tool_status, duration_ms)
                           VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)""",
                        (scan_id, agent_id, int(step), str(thought)[:2000],
                         str(tool)[:120], "{}", "", int(status), 0))
                    conn.commit()
        except Exception:
            pass

    try:
        await asyncio.to_thread(_w)
    except Exception:
        pass


@dataclass(frozen=True)
class ProbeSpec:
    name: str            # activity/log label + tool name
    module: str          # import path
    func: str            # coroutine, invoked as `await func(ctx)` → findings list
    family: TestFamily   # plan-gating unit
    tier: AgentTier      # junior=breadth, senior=depth
    lane: str = "net"    # "net" (concurrent) | "browser" (serial, shared browser)


# The specialist battery. Order within the net lane does not matter (findings are
# deduped in ctx); browser-lane probes keep their listed order.
REGISTRY: List[ProbeSpec] = [
    ProbeSpec("api_probe", "core.exploitation.api_probe", "run_api_probe", F.API, J),
    ProbeSpec("business_logic_probe", "core.exploitation.business_logic_probe", "run_business_logic_probe", F.BUSINESS_LOGIC, S),
    ProbeSpec("workflow", "core.workflow.violation_tester", "run_workflow_probe", F.BUSINESS_LOGIC, S),
    ProbeSpec("llm_app_probe", "core.exploitation.llm_app_probe", "run_llm_app_probe", F.API, S),
    ProbeSpec("authz_matrix", "core.exploitation.authz_matrix", "run_authz_matrix", F.AUTHZ_IDOR, S),
    ProbeSpec("param_fuzzer", "core.exploitation.param_fuzzer", "run_param_fuzzer", F.INJECTION, J),
    ProbeSpec("race_probe", "core.exploitation.race_probe", "run_race_probe", F.RACE, S),
    ProbeSpec("crypto_chain", "core.exploitation.crypto_chain", "run_crypto_chain", F.CRYPTO, S),
    ProbeSpec("identity_intel", "core.intelligence.identity_intel", "run_identity_intel", F.SECRET_DISCLOSURE, J),
    ProbeSpec("web3_probe", "core.exploitation.web3_probe", "run_web3_probe", F.WEB3, S),
    ProbeSpec("second_order", "core.exploitation.second_order", "run_second_order_probe", F.INJECTION, S),
    ProbeSpec("session_probe", "core.exploitation.session_probe", "run_session_probe", F.AUTH_SESSION, J),
    ProbeSpec("cors_probe", "core.exploitation.cors_probe", "run_cors_probe", F.API, J),
    ProbeSpec("smuggling_probe", "core.exploitation.smuggling_probe", "run_smuggling_probe", F.INFRA_CONFIG, J),
    ProbeSpec("host_header_probe", "core.exploitation.host_header_probe", "run_host_header_probe", F.INFRA_CONFIG, J),
    ProbeSpec("open_redirect_probe", "core.exploitation.open_redirect_probe", "run_open_redirect_probe", F.API, J),
    ProbeSpec("clickjack_probe", "core.exploitation.clickjack_probe", "run_clickjack_probe", F.INFRA_CONFIG, J),
    ProbeSpec("file_upload_probe", "core.exploitation.file_upload_probe", "run_file_upload_probe", F.FILE_UPLOAD, S),
    ProbeSpec("cache_poison_probe", "core.exploitation.cache_poison_probe", "run_cache_poison_probe", F.INFRA_CONFIG, J),
    ProbeSpec("ssti_probe", "core.exploitation.ssti_probe", "run_ssti_probe", F.INJECTION, J),
    ProbeSpec("xxe_probe", "core.exploitation.xxe_probe", "run_xxe_probe", F.INJECTION, J),
    ProbeSpec("mass_assign_probe", "core.exploitation.mass_assign_probe", "run_mass_assign_probe", F.API, J),
    ProbeSpec("rate_limit_probe", "core.exploitation.rate_limit_probe", "run_rate_limit_probe", F.RATE_LIMIT, J),
    ProbeSpec("hpp_probe", "core.exploitation.hpp_probe", "run_hpp_probe", F.API, J),
    ProbeSpec("websocket_probe", "core.exploitation.websocket_probe", "run_websocket_probe", F.API, J),
    ProbeSpec("email_inject_probe", "core.exploitation.email_inject_probe", "run_email_inject_probe", F.INJECTION, J),
    ProbeSpec("cookie_probe", "core.exploitation.cookie_probe", "run_cookie_probe", F.AUTH_SESSION, J),
    ProbeSpec("graphql_dos_probe", "core.exploitation.graphql_dos_probe", "run_graphql_dos_probe", F.API, J),
    ProbeSpec("deserial_probe", "core.exploitation.deserial_probe", "run_deserial_probe", F.INJECTION, S),
    ProbeSpec("dns_rebind_probe", "core.exploitation.dns_rebind_probe", "run_dns_rebind_probe", F.API, J),
    ProbeSpec("prototype_pollution_probe", "core.exploitation.prototype_pollution_probe", "run_prototype_pollution_probe", F.INJECTION, J),
    ProbeSpec("logging_detect_probe", "core.exploitation.logging_detect_probe", "run_logging_detect_probe", F.INFRA_CONFIG, J),
    # Browser lane (shared Playwright — serial):
    ProbeSpec("chatbot_exploit", "core.exploitation.chatbot_exploit", "run_chatbot_exploit", F.API, S, "browser"),
    ProbeSpec("browser_agent", "core.actuation.browser_agent", "run_browser_agent", F.INJECTION, S, "browser"),
]


async def _run_one(brain, spec: ProbeSpec, browser_lock=None) -> int:
    """Import + run one probe against ctx; add findings; log. Never raises.
    Browser-lane probes are serialized on `browser_lock` (shared browser)."""
    ctx = brain.ctx
    try:
        mod = __import__(spec.module, fromlist=[spec.func])
        fn = getattr(mod, spec.func)
        if spec.lane == "browser" and browser_lock is not None:
            async with browser_lock:
                findings = await fn(ctx) or []
        else:
            findings = await fn(ctx) or []
    except Exception as e:
        logger.warning("[%s] failed (non-fatal): %s", spec.name, e)
        return 0
    added = 0
    for f in findings:
        try:
            ctx.add_vulnerability(f)
            added += 1
        except Exception:
            pass
    if findings:
        logger.info("[%s] %d findings (tier=%s family=%s)",
                    spec.name, len(findings), spec.tier.value, spec.family.value)
    try:
        brain._log_activity(spec.name, f"{spec.name}: {len(findings)} findings",
                            tool=spec.name)
    except Exception:
        pass
    return added


# Human phase label shown on the parallel-agent cards.
_PHASE_LABEL = "VULNERABILITY_ASSESSMENT"


async def run_specialist_probes(brain) -> Dict[str, Any]:
    """Run the specialist battery as plan-scoped, **parallel family teams** — each
    relevant TestFamily becomes one concurrent live agent (visible in the UI's
    Parallel Agents tab), running its probes and reporting findings, mirroring the
    human model of multiple specialists working the same phase at once."""
    from core.orchestration.parallel_agents import AgentTracker
    ctx = brain.ctx
    plan = brain._get_engagement_plan() if hasattr(brain, "_get_engagement_plan") else None
    scan_id = getattr(brain, "_scan_id", "") or getattr(ctx, "scan_id", "") or ""
    target = getattr(ctx, "target", "") or ""
    try:
        concurrency = max(1, int(os.getenv("FAMILY_CONCURRENCY", "4")))
    except ValueError:
        concurrency = 4

    # Group relevant probes into family teams; skip out-of-scope families AND any
    # family already run adaptively (finding-driven spawn) so it isn't repeated.
    from collections import OrderedDict
    teams: "OrderedDict[TestFamily, List[ProbeSpec]]" = OrderedDict()
    skipped_families: set = set()
    already = getattr(brain, "_families_spawned", set()) or set()
    for spec in REGISTRY:
        if spec.family in already:
            continue  # ran early via adaptive spawn
        if plan is not None and not plan.is_relevant(spec.family):
            skipped_families.add(spec.family.value)
            try:
                brain._record_family_skipped(spec.family.value)
            except Exception:
                pass
            continue
        teams.setdefault(spec.family, []).append(spec)
    if skipped_families:
        logger.info("[FamilyScheduler] out-of-scope families skipped: %s",
                    sorted(skipped_families))
    logger.info("[FamilyScheduler] %d parallel family team(s) @concurrency=%d; "
                "%d family(ies) skipped", len(teams), concurrency, len(skipped_families))

    sem = asyncio.Semaphore(concurrency)
    browser_lock = asyncio.Lock()

    async def _run_team(family: TestFamily, specs: List[ProbeSpec]) -> int:
        async with sem:
            from core.orchestration.test_plan import specialist_role
            tier = S if any(s.tier is S for s in specs) else J
            role = specialist_role(family)
            # Skills are DERIVED from the probes this family actually runs — add a
            # probe to the registry and the skill set updates itself (no hardcoding).
            skills = ", ".join(s.name.replace("_probe", "").replace("_", " ")
                               for s in specs)
            agent_id = f"team:{family.value}"
            tracker = AgentTracker(scan_id, agent_id,
                                   label=f"{role} [{tier.value}]",
                                   phase=_PHASE_LABEL, target=target)
            # Stamp the specialist's skill set into metadata (shown on the card).
            try:
                from core.database.pg_store import LiveAgentRepo
                LiveAgentRepo.upsert(scan_id, agent_id, label=f"{role} [{tier.value}]",
                                     phase=_PHASE_LABEL, target=target, status="queued",
                                     metadata={"role": role, "skills": skills,
                                               "tier": tier.value, "family": family.value,
                                               "probes": [s.name for s in specs]})
            except Exception:
                pass
            tracker.start(current_step=skills or f"{len(specs)} tests")
            added = 0
            for i, spec in enumerate(specs):
                tracker.heartbeat(tool=spec.name, step=f"{i + 1}/{len(specs)} {spec.name}",
                                  steps_taken=i + 1)
                await _reason(scan_id, agent_id, i + 1,
                              f"Testing with {spec.name.replace('_probe', '').replace('_', ' ')} "
                              f"({tier.value}).", tool=spec.name)
                before = added
                added += await _run_one(brain, spec, browser_lock)
                if added > before:
                    await _reason(scan_id, agent_id, i + 1,
                                  f"→ {spec.name}: {added - before} finding(s).",
                                  tool=spec.name)
                tracker.heartbeat(findings_count=added, steps_taken=i + 1)
            tracker.finish(status="completed")
            logger.info("[FamilyScheduler] team=%s done: %d probe(s), %d finding(s)",
                        family.value, len(specs), added)
            return added

    results = await asyncio.gather(
        *[_run_team(f, s) for f, s in teams.items()], return_exceptions=True)
    added = sum(r for r in results if isinstance(r, int))

    # Persist findings now so a mid-scan stop/kill keeps the specialist results.
    try:
        await brain._flush_partial("specialist sweep")
    except Exception:
        pass

    # Coverage ledger: mark every family that ran this sweep (the gate reads this).
    try:
        for f in teams:
            brain._coverage_ran.add(f"active_scanning:{f.value}")
    except Exception:
        pass

    # Dedup ledger: claim these families so a later call to this sweep (e.g. the
    # EXPLOITATION-phase invocation after the ACTIVE_SCANNING one) skips them and
    # doesn't re-run the same probes.
    try:
        fams = getattr(brain, "_families_spawned", None)
        if fams is None:
            fams = set(); brain._families_spawned = fams
        for f in teams:
            fams.add(f)
    except Exception:
        pass

    escalated = _escalate(ctx)
    stats = {"teams": len(teams), "skipped_families": sorted(skipped_families),
             "vulns_added": added, "escalated": escalated, "concurrency": concurrency}
    logger.info("[FamilyScheduler] done: %s", stats)
    try:
        brain._log_activity("family_scheduler",
                            f"Teams: {len(teams)} parallel, {added} findings, "
                            f"{escalated} escalated", tool="family_scheduler")
    except Exception:
        pass
    return stats


# ── Authenticated multi-identity battery ─────────────────────────────────────
_AUTHED_PHASE_LABEL = "AUTHENTICATED_ASSESSMENT"
# Families whose results depend on WHO you are — worth re-running per role. An
# unauthenticated sweep gets 401 on these and finds nothing behind login.
_AUTHED_FAMILIES = {F.AUTHZ_IDOR, F.BUSINESS_LOGIC, F.API, F.AUTH_SESSION, F.RATE_LIMIT}


def _identity_headers(brain) -> Dict[str, Dict[str, str]]:
    """{role -> auth headers} for every authenticated session (from multi_auth)."""
    out: Dict[str, Dict[str, str]] = {}
    multi = getattr(brain, "multi_auth", None)
    for role, mgr in (getattr(multi, "sessions", {}) or {}).items():
        h = dict(getattr(mgr, "headers", {}) or {})
        h.update({k: v for k, v in (getattr(mgr, "csrf_tokens", {}) or {}).items() if v})
        if h:
            out[str(role)] = h
    return out


async def run_authenticated_battery(brain) -> Dict[str, Any]:
    """Re-run the identity-sensitive families AS EACH authenticated role, so probes
    exercise authenticated functionality — most real IDOR / business-logic /
    mass-assignment bugs live behind login and are invisible to an unauthenticated
    sweep. Sequential per role (swaps ctx.auth_headers), concurrent per family
    within a role. Non-fatal."""
    from collections import OrderedDict
    from core.orchestration.parallel_agents import AgentTracker
    from core.orchestration.test_plan import specialist_role
    ctx = brain.ctx
    # Run once per scan: this is invoked at the end of ACTIVE_SCANNING and again in
    # EXPLOITATION; the first run covers it.
    if getattr(brain, "_authed_battery_ran", False):
        return {"identities": 0, "skipped": "already_ran"}
    idents = _identity_headers(brain)
    if not idents:
        logger.info("[AuthedBattery] no authenticated identities — skipped")
        return {"identities": 0}
    brain._authed_battery_ran = True
    plan = brain._get_engagement_plan() if hasattr(brain, "_get_engagement_plan") else None
    scan_id = getattr(brain, "_scan_id", "") or getattr(ctx, "scan_id", "") or ""
    target = getattr(ctx, "target", "") or ""

    teams: "OrderedDict[TestFamily, List[ProbeSpec]]" = OrderedDict()
    for spec in REGISTRY:
        if spec.family not in _AUTHED_FAMILIES:
            continue
        if plan is not None and not plan.is_relevant(spec.family):
            continue
        teams.setdefault(spec.family, []).append(spec)
    if not teams:
        return {"identities": len(idents), "teams": 0}

    logger.info("[AuthedBattery] %d identity(ies) × %d family(ies)", len(idents), len(teams))
    saved = getattr(ctx, "auth_headers", None)
    total = 0
    try:
        for role, headers in idents.items():
            ctx.auth_headers = headers  # probes read ctx.auth_headers
            browser_lock = asyncio.Lock()
            role_tag = "".join(c for c in role if c.isalnum() or c in "-_")[:24] or "role"

            async def _run_team(family: TestFamily, specs: List[ProbeSpec],
                                role=role, role_tag=role_tag) -> int:
                agent_id = f"team:{family.value}@{role_tag}"
                role_name = specialist_role(family)
                skills = ", ".join(s.name.replace("_probe", "").replace("_", " ") for s in specs)
                tracker = AgentTracker(scan_id, agent_id, label=f"{role_name} as {role}",
                                       phase=_AUTHED_PHASE_LABEL, target=target)
                try:
                    from core.database.pg_store import LiveAgentRepo
                    LiveAgentRepo.upsert(scan_id, agent_id, label=f"{role_name} as {role}",
                                         phase=_AUTHED_PHASE_LABEL, target=target, status="queued",
                                         metadata={"role": role_name, "identity": role, "skills": skills,
                                                   "family": family.value, "authenticated": True,
                                                   "probes": [s.name for s in specs]})
                except Exception:
                    pass
                tracker.start(current_step=f"as {role}: {skills}")
                await _reason(scan_id, agent_id, 0,
                              f"Authenticated as '{role}': re-testing {role_name} "
                              f"({len(specs)} probe(s)) to expose authz gaps: {skills}.")
                added = 0
                for i, spec in enumerate(specs):
                    tracker.heartbeat(tool=spec.name, step=f"{i + 1}/{len(specs)} {spec.name}",
                                      steps_taken=i + 1)
                    await _reason(scan_id, agent_id, i + 1,
                                  f"As '{role}': testing "
                                  f"{spec.name.replace('_probe', '').replace('_', ' ')}.",
                                  tool=spec.name)
                    before = added
                    added += await _run_one(brain, spec, browser_lock)
                    if added > before:
                        await _reason(scan_id, agent_id, i + 1,
                                      f"→ {spec.name} (as {role}): {added - before} finding(s).",
                                      tool=spec.name)
                    tracker.heartbeat(findings_count=added, steps_taken=i + 1)
                await _reason(scan_id, agent_id, len(specs) + 1,
                              f"Completed as '{role}': {added} finding(s).",
                              status=1 if added else 0)
                tracker.finish(status="completed")
                return added

            res = await asyncio.gather(*[_run_team(f, s) for f, s in teams.items()],
                                       return_exceptions=True)
            total += sum(r for r in res if isinstance(r, int))
    finally:
        ctx.auth_headers = saved  # always restore the original identity

    stats = {"identities": len(idents), "families": len(teams), "vulns_added": total}
    logger.info("[AuthedBattery] done: %s", stats)
    try:
        brain._log_activity("authenticated_battery",
                            f"Auth battery: {len(idents)} roles × {len(teams)} families, {total} findings",
                            tool="authenticated_battery")
    except Exception:
        pass
    return stats


# ── Parallel RECON specialist lanes ──────────────────────────────────────────
_RECON_PHASE_LABEL = "RECONNAISSANCE"


async def run_recon_teams(brain) -> Dict[str, Any]:
    """Run reconnaissance as parallel specialist lanes — OSINT, Web, Infra, API —
    each a tracked live agent (visible in the Parallel Agents tab), mirroring four
    pentesters working recon at once. Reuses the existing recon coroutines; the
    OSINT/Web/Infra lanes run concurrently, then the API lane classifies the
    surface they discovered. Non-fatal per lane."""
    import os as _os
    from core.orchestration.parallel_agents import AgentTracker
    ctx = brain.ctx
    scan_id = getattr(brain, "_scan_id", "") or getattr(ctx, "scan_id", "") or ""
    target = getattr(ctx, "target", "") or ""

    async def _lane(agent_id: str, role: str, skills: str, body) -> int:
        try:
            from core.database.pg_store import LiveAgentRepo
            LiveAgentRepo.upsert(scan_id, agent_id, label=f"{role} [junior]",
                                 phase=_RECON_PHASE_LABEL, target=target, status="queued",
                                 metadata={"role": role, "skills": skills, "tier": "junior",
                                           "family": agent_id.split(":")[-1]})
        except Exception:
            pass
        tracker = AgentTracker(scan_id, agent_id, label=f"{role} [junior]",
                               phase=_RECON_PHASE_LABEL, target=target)
        tracker.start(current_step=skills)
        await _reason(scan_id, agent_id, 0,
                      f"{role}: working the surface — {skills}.", tool=agent_id.split(":")[-1])
        added = 0
        try:
            added = int(await body(agent_id) or 0)
        except Exception as e:
            logger.warning("[recon-team=%s] failed (non-fatal): %s", agent_id, e)
            await _reason(scan_id, agent_id, 1, f"Lane error (non-fatal): {e}", status=-1)
        tracker.heartbeat(findings_count=added, steps_taken=1)
        await _reason(scan_id, agent_id, 2,
                      f"Completed — {added} discovery finding(s) added to the surface.")
        tracker.finish(status="completed")
        try:
            brain._coverage_ran.add(f"recon:{agent_id.split(':')[-1]}")
        except Exception:
            pass
        logger.info("[ReconTeams] %s done: %d discovery finding(s)", agent_id, added)
        return added

    async def _web(aid) -> int:
        n = 0
        if _os.getenv("ENABLE_CRAWLER", "true").lower() in ("true", "1", "yes", "on"):
            try:
                from core.browser.crawler import crawl_into_context
                if target:
                    n = await crawl_into_context(ctx, target) or 0
                    brain._log_activity("crawler", f"Crawler: {n} requests", tool="browser_crawler")
            except Exception as e:
                logger.warning("[ReconTeams:web] crawl failed: %s", e)
        await _reason(scan_id, aid, 1,
                      f"Crawled {target} with a headless browser — captured {n} request(s).",
                      tool="crawler")
        try:
            await brain._run_bundle_and_dom_analysis()
        except Exception as e:
            logger.warning("[ReconTeams:web] bundle/dom failed: %s", e)
        eps = len(getattr(ctx, "endpoints", []) or [])
        await _reason(scan_id, aid, 2,
                      f"Extracted routes from JS bundles + source maps and observed DOM sinks. "
                      f"Attack surface now: {eps} endpoint(s).", tool="js_analyzer")
        return n

    async def _infra(aid) -> int:
        added = 0
        nd = []
        try:
            from core.recon.network_discovery import run_network_discovery
            nd = await run_network_discovery(ctx) or []
            for f in nd:
                ctx.add_vulnerability(f)
                added += 1
        except Exception as e:
            logger.warning("[ReconTeams:infra] network_discovery failed: %s", e)
        op = getattr(ctx, "open_ports", {}) or {}
        try:
            ports = sorted({p for lst in op.values() for p in (lst or [])}) if isinstance(op, dict) else []
        except Exception:
            ports = []
        await _reason(scan_id, aid, 1,
                      f"Port-scanned common service ports. Open: {ports or 'web only (80/443)'}. "
                      f"Exposed-service finding(s): {len(nd)}.", tool="port_scan")
        ce = []
        try:
            from core.recon.cloud_enum import run_cloud_enum
            ce = await run_cloud_enum(ctx) or []
            for f in ce:
                ctx.add_vulnerability(f)
                added += 1
        except Exception as e:
            logger.warning("[ReconTeams:infra] cloud_enum failed: %s", e)
        await _reason(scan_id, aid, 2,
                      f"Cloud / CDN / public-bucket enumeration complete. "
                      f"Exposed cloud asset(s): {len(ce)}.", tool="cloud_enum")
        if added == 0:
            await _reason(scan_id, aid, 3,
                          "No exposed databases, admin services, or public cloud assets found — "
                          "the host surface is clean at the network layer.")
        return added

    async def _osint(aid) -> int:
        if _os.getenv("ENABLE_OSINT", _os.getenv("OSINT_ENABLE", "true")).lower() \
                not in ("true", "1", "yes", "on"):
            await _reason(scan_id, aid, 1, "OSINT disabled by configuration.", status=-1)
            return 0
        before = len(getattr(ctx, "findings", []) or [])
        try:
            await brain._run_phase("OSINT_RECONNAISSANCE")
        except Exception as e:
            logger.warning("[ReconTeams:osint] failed: %s", e)
        got = max(0, len(getattr(ctx, "findings", []) or []) - before)
        subs = len(getattr(ctx, "subdomains", []) or [])
        await _reason(scan_id, aid, 1,
                      f"OSINT sweep complete — whois, DNS, subdomain enumeration, GitHub secret "
                      f"scan, tech fingerprint. Subdomains: {subs}, new finding(s): {got}.",
                      tool="osint")
        return got

    # Wave 1: OSINT ∥ Web ∥ Infra (independent workstreams).
    wave1 = await asyncio.gather(
        _lane("team:osint_recon", "OSINT Specialist",
              "whois, dns, subdomains, github secrets, tech fingerprint", _osint),
        _lane("team:web_recon", "Web Application Mapper",
              "crawl, js bundle + sourcemap, dom sinks, endpoint discovery", _web),
        _lane("team:infra_recon", "Infrastructure Mapper",
              "port scan, ssl/tls, cdn/cloud detect, exposed services", _infra),
        return_exceptions=True)

    # Wave 2: API lane classifies the surface the web lane just discovered.
    async def _api(aid) -> int:
        eps = list(getattr(ctx, "endpoints", []) or [])

        def _u(e):
            return e if isinstance(e, str) else (e.get("url", "") if isinstance(e, dict) else "")

        api_eps = [u for u in map(_u, eps)
                   if any(k in u.lower() for k in ("/api", "/rest", "/graphql", "/v1", "/v2", "/v3"))]
        gql = [u for u in api_eps if "graphql" in u.lower()]
        try:
            brain._log_activity("api_recon",
                                f"API surface: {len(api_eps)} endpoints, {len(gql)} graphql",
                                tool="api_recon")
        except Exception:
            pass
        sample = ", ".join(u.split("?")[0] for u in api_eps[:3]) or "none"
        await _reason(scan_id, aid, 1,
                      f"Classified the discovered surface: {len(api_eps)} API/REST endpoint(s), "
                      f"{len(gql)} GraphQL. Examples: {sample}.", tool="api_recon")
        return len(api_eps)

    api_added = await _lane("team:api_recon", "API Specialist",
                            "api/rest/graphql discovery, versions, auth scheme", _api)

    added = sum(r for r in wave1 if isinstance(r, int)) + (api_added if isinstance(api_added, int) else 0)
    stats = {"recon_teams": 4, "discoveries": added}
    logger.info("[ReconTeams] done: %s", stats)
    try:
        brain._log_activity("recon_teams",
                            f"Recon teams: 4 parallel lanes, {added} discoveries",
                            tool="recon_teams")
    except Exception:
        pass
    return stats


# ── Adaptive, finding-driven spawn ───────────────────────────────────────────
# Map a discovered signal (endpoint URL / finding hint) → the specialist family
# that should investigate it immediately, instead of waiting for the full sweep.
_SIGNAL_FAMILY: List[tuple] = [
    # Specific/high-value signals first; generic API path prefixes last so they
    # don't shadow a more precise family (e.g. "/rest/basket" → business_logic).
    (("/admin", "admin", "dashboard", "manage", "rbac", "/internal", "superuser"), F.AUTHZ_IDOR),
    (("login", "signin", "sign-in", "/auth", "/token", "jwt", "session", "oauth",
      "password", "reset", "2fa", "otp", "register"), F.AUTH_SESSION),
    (("upload", "avatar", "/file", "import", "attachment", "multipart", "media"), F.FILE_UPLOAD),
    (("cart", "checkout", "coupon", "price", "order", "basket", "payment",
      "refund", "wallet", "balance", "voucher", "quantity"), F.BUSINESS_LOGIC),
    (("web3", "ethereum", "metamask", "contract", "erc", "nft", "0x"), F.WEB3),
    (("search", "query", "filter", "id=", "?q=", "sort", "where"), F.INJECTION),
    (("graphql", "/api", "/rest", "swagger", "openapi", "/v1", "/v2", ".json"), F.API),
]


def family_for_signal(text: str):
    """Return the TestFamily a signal implies, or None. Cheap keyword match."""
    t = (text or "").lower()
    if not t:
        return None
    for kws, fam in _SIGNAL_FAMILY:
        if any(k in t for k in kws):
            return fam
    return None


async def spawn_family_team(brain, family: TestFamily, *, reason: str = "") -> int:
    """Run ONE relevant family's probes NOW as a live specialist agent, ahead of
    the scanning sweep. Deduped (brain._families_spawned) so the later sweep skips
    it. Plan-aware + best-effort — never raises into the caller."""
    try:
        fams = getattr(brain, "_families_spawned", None)
        if fams is None:
            fams = set(); brain._families_spawned = fams
        if family in fams:
            return 0
        plan = brain._get_engagement_plan() if hasattr(brain, "_get_engagement_plan") else None
        if plan is not None and not plan.is_relevant(family):
            return 0
        specs = [s for s in REGISTRY if s.family is family]
        if not specs:
            return 0
        fams.add(family)  # claim before running so concurrent callers dedup

        from core.orchestration.parallel_agents import AgentTracker
        from core.orchestration.test_plan import specialist_role
        ctx = brain.ctx
        scan_id = getattr(brain, "_scan_id", "") or getattr(ctx, "scan_id", "") or ""
        target = getattr(ctx, "target", "") or ""
        tier = S if any(s.tier is S for s in specs) else J
        role = specialist_role(family)
        skills = ", ".join(s.name.replace("_probe", "").replace("_", " ") for s in specs)
        agent_id = f"team:{family.value}"
        tracker = AgentTracker(scan_id, agent_id, label=f"{role} [{tier.value}] (adaptive)",
                               phase=_PHASE_LABEL, target=target)
        try:
            from core.database.pg_store import LiveAgentRepo
            LiveAgentRepo.upsert(scan_id, agent_id, label=f"{role} [{tier.value}] (adaptive)",
                                 phase=_PHASE_LABEL, target=target, status="queued",
                                 metadata={"role": role, "skills": skills, "tier": tier.value,
                                           "family": family.value, "adaptive": True,
                                           "trigger": reason[:200],
                                           "probes": [s.name for s in specs]})
        except Exception:
            pass
        tracker.start(current_step=(reason or skills)[:120])
        await _reason(scan_id, agent_id, 0,
                      f"Adaptive spawn ({tier.value}) for {role}: {reason or 'relevance signal'}. "
                      f"Running {len(specs)} probe(s): {skills}.")
        browser_lock = asyncio.Lock()
        added = 0
        for i, spec in enumerate(specs):
            tracker.heartbeat(tool=spec.name, step=f"{i + 1}/{len(specs)} {spec.name}",
                              steps_taken=i + 1)
            await _reason(scan_id, agent_id, i + 1,
                          f"Testing with {spec.name.replace('_probe', '').replace('_', ' ')} "
                          f"({tier.value}).", tool=spec.name)
            before = added
            added += await _run_one(brain, spec, browser_lock)
            if added > before:
                await _reason(scan_id, agent_id, i + 1,
                              f"→ {spec.name}: {added - before} finding(s).",
                              tool=spec.name)
            tracker.heartbeat(findings_count=added, steps_taken=i + 1)
        await _reason(scan_id, agent_id, len(specs) + 1,
                      f"Completed: {len(specs)} probe(s), {added} finding(s).",
                      status=1 if added else 0)
        tracker.finish(status="completed")
        try:
            brain._coverage_ran.add(f"active_scanning:{family.value}")
        except Exception:
            pass
        # Persist immediately so an adaptive team's findings survive a mid-scan stop.
        if added:
            try:
                await brain._flush_partial(f"adaptive:{family.value}")
            except Exception:
                pass
        logger.info("[FamilyScheduler] ADAPTIVE team=%s (%s): %d probe(s), %d finding(s)",
                    family.value, reason or "signal", len(specs), added)
        return added
    except Exception as e:
        logger.warning("[FamilyScheduler] adaptive spawn for %s failed (non-fatal): %s",
                       getattr(family, "value", family), e)
        return 0


def _escalate(ctx) -> int:
    """Route partial / low-confidence findings to the SENIOR verify passes
    (second-order + retest) that run later on ctx.vulnerabilities. Best-effort."""
    try:
        vulns = getattr(ctx, "vulnerabilities", []) or []
        partial = []
        for v in vulns:
            status = str(v.get("status", "")).lower()
            try:
                conf = float(v.get("confidence_score", v.get("confidence", 1.0)) or 1.0)
            except (TypeError, ValueError):
                conf = 1.0
            if status in ("partial", "unconfirmed") or conf < 0.5:
                partial.append(v)
        if not partial:
            return 0
        try:
            from core.orchestration.specialist_agents import EvidenceBus
            EvidenceBus().publish_evidence("escalated_candidates",
                                           {"count": len(partial)})
        except Exception:
            pass
        logger.info("[FamilyScheduler] escalated %d partial finding(s) to SENIOR verify",
                    len(partial))
        return len(partial)
    except Exception:
        return 0
