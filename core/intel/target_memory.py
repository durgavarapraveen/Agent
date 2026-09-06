"""Adaptive per-target memory.

Remembers, across scans of the SAME target, what worked so subsequent scans
start with a warm recipe rather than re-discovering from scratch:

  - Which login endpoint responded 200 with a JWT
  - Which JSON body shape ({"email":...} vs {"username":...} vs form) succeeded
  - Which WAF was detected (so we start with matching evasion tampers)
  - Which payload families were BLOCKED (skip on next run)
  - Which endpoints and subdomains we already know exist
  - Which technologies were fingerprinted

Loaded at scan start (`load_intel(target)`), updated post-scan
(`record_scan_intel(target, ctx)`).
"""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _canonical_target(t: str) -> str:
    if not t:
        return ""
    if "://" in t:
        t = urlparse(t).hostname or t
    return t.lower().strip().rstrip("/")


def load_intel(target: str) -> Dict[str, Any]:
    """Load prior intel for this target — call this at scan start.

    Returns dict with working_login_endpoints, waf_detected, known_endpoints,
    known_subdomains, known_tech, prior_scan_ids. Empty dict if first scan."""
    from core.database.pg_store import DatabaseManager
    import psycopg2.extras
    key = _canonical_target(target)
    if not key:
        return {}
    try:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM target_intel WHERE target = %s", (key,))
                row = cur.fetchone()
                if not row:
                    return {}
                return {k: v for k, v in row.items() if v is not None}
    except Exception as e:
        logger.debug(f"[TargetMemory] load failed: {e}")
        return {}


def record_scan_intel(target: str, ctx, scan_id: str) -> None:
    """Extract what worked from this ctx and merge into target_intel."""
    from core.database.pg_store import DatabaseManager, AuthBypassRepo
    key = _canonical_target(target)
    if not key:
        return
    try:
        # Working login endpoints: any auth_bypass technique in ('sqli_bypass',
        # 'mass_assign_admin', 'credential_replay') → its login_url worked.
        bypasses = AuthBypassRepo.get_by_scan(scan_id) or []
        working_login = list({b.get("login_url", "") for b in bypasses
                                if b.get("login_url") and b.get("response_status") in (200, 201)})
        # Body shapes that succeeded — parse the payload JSON keys
        body_shapes = []
        for b in bypasses:
            try:
                p = json.loads(b.get("payload", ""))
                if isinstance(p, dict):
                    body_shapes.append(sorted(p.keys()))
            except Exception:
                continue
        body_shapes = [list(s) for s in {tuple(s) for s in body_shapes}]

        # Known intel from ctx
        subs = list({s if isinstance(s, str) else (s.get("name") or "")
                      for s in (getattr(ctx, "subdomains", []) or [])})
        eps = list({e if isinstance(e, str) else (e.get("url") or "")
                     for e in (getattr(ctx, "endpoints", []) or [])})[:500]
        techs = getattr(ctx, "technologies", {}) or {}
        waf = ""
        for host, tech_list in (techs or {}).items():
            for t in (tech_list if isinstance(tech_list, list) else [tech_list]):
                if isinstance(t, str) and "waf" in t.lower():
                    waf = t; break
            if waf: break

        # Prior scan history — append this scan_id
        cur_intel = load_intel(target)
        prior = list(cur_intel.get("prior_scan_ids") or [])
        if scan_id and scan_id not in prior:
            prior.append(scan_id)
        prior = prior[-20:]

        # Merge (union) with prior known intel
        prev_subs = list(cur_intel.get("known_subdomains") or [])
        prev_eps  = list(cur_intel.get("known_endpoints") or [])
        merged_subs = list(dict.fromkeys(prev_subs + subs))[:500]
        merged_eps  = list(dict.fromkeys(prev_eps + eps))[:2000]
        prev_login = list(cur_intel.get("working_login_endpoints") or [])
        merged_login = list(dict.fromkeys(prev_login + working_login))
        prev_shapes = list(cur_intel.get("working_body_shapes") or [])
        merged_shapes = [list(s) for s in {tuple(s) for s in prev_shapes + body_shapes}]

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO target_intel
                      (target, working_login_endpoints, working_body_shapes, waf_detected,
                       known_endpoints, known_subdomains, known_tech, prior_scan_ids)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (target) DO UPDATE SET
                      working_login_endpoints = EXCLUDED.working_login_endpoints,
                      working_body_shapes = EXCLUDED.working_body_shapes,
                      waf_detected = COALESCE(NULLIF(EXCLUDED.waf_detected, ''), target_intel.waf_detected),
                      known_endpoints = EXCLUDED.known_endpoints,
                      known_subdomains = EXCLUDED.known_subdomains,
                      known_tech = EXCLUDED.known_tech,
                      prior_scan_ids = EXCLUDED.prior_scan_ids,
                      updated_at = NOW()
                """, (key, json.dumps(merged_login), json.dumps(merged_shapes),
                      waf, json.dumps(merged_eps), json.dumps(merged_subs),
                      json.dumps(techs, default=str), json.dumps(prior)))
                conn.commit()
        logger.info(f"[TargetMemory] Saved intel for {key}: "
                    f"{len(merged_login)} working logins, {len(merged_shapes)} body shapes, "
                    f"{len(merged_eps)} endpoints, {len(merged_subs)} subs")
    except Exception as e:
        logger.warning(f"[TargetMemory] record failed: {e}")


async def verify_and_refresh(ctx, target: str,
                                fingerprint_threshold_days: int = 3) -> Dict[str, Any]:
    """Prior intel goes stale — targets change. This runs AFTER prime_ctx and:

      1. **Fingerprint check** on the base URL: compare server header +
         status + tech stack vs stored. If materially different (server
         changed, framework changed, IP changed), mark intel STALE →
         invalidate primed endpoints/subs and force full re-discovery.
         Prevents priming from a migrated target.
      2. **Liveness re-check** on primed endpoints (parallel HEAD in
         batches): 404/410/5xx → drop from ctx.endpoints (was removed).
         200/301/302/401/403 → keep (still real).
      3. **Never trust prior findings** — those are re-run every scan
         through live tests; only DISCOVERY hints are reused.

    Returns stats dict: fingerprint_changed, endpoints_dropped, endpoints_kept.
    """
    import httpx, asyncio as _aio
    from urllib.parse import urlparse
    stats = {"fingerprint_changed": False, "endpoints_dropped": 0,
             "endpoints_kept": 0, "subs_dropped": 0, "subs_kept": 0}
    intel = load_intel(target)
    if not intel:
        return stats

    # Determine base URL for fingerprint
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    prior_fingerprint = (intel.get("metadata") or {}).get("fingerprint") or {}

    async with httpx.AsyncClient(follow_redirects=True, timeout=8, verify=False) as client:
        # ── Fingerprint check
        try:
            r = await client.get(base)
            current_fp = {
                "status": r.status_code,
                "server": r.headers.get("server", "")[:60],
                "x_powered_by": r.headers.get("x-powered-by", "")[:60],
                "content_type": r.headers.get("content-type", "")[:60],
                "cf_ray": bool(r.headers.get("cf-ray")),
                "body_len_bucket": len(r.text or "") // 1000 * 1000,
            }
        except Exception:
            current_fp = {"error": "unreachable"}
        # Compare — any of {status, server, x_powered_by} changing is material
        material_keys = ("server", "x_powered_by")
        if prior_fingerprint:
            for k in material_keys:
                if prior_fingerprint.get(k) and current_fp.get(k) and \
                   prior_fingerprint[k] != current_fp[k]:
                    stats["fingerprint_changed"] = True
                    logger.warning(f"[TargetMemory] Fingerprint changed for {target}: "
                                    f"{k} was {prior_fingerprint[k]!r}, now {current_fp[k]!r} — "
                                    f"invalidating primed endpoints, forcing re-discovery")
                    break
        # Save current fingerprint for next run regardless
        try:
            from core.database.pg_store import DatabaseManager
            import json as _json
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE target_intel SET metadata = jsonb_set(
                            COALESCE(metadata, '{}'::jsonb),
                            '{fingerprint}', %s::jsonb, true), updated_at = NOW()
                        WHERE target = %s
                    """, (_json.dumps(current_fp), _canonical_target(target)))
                    conn.commit()
        except Exception:
            pass

        # ── If fingerprint drifted, drop primed endpoints/subs entirely
        if stats["fingerprint_changed"]:
            try:
                ctx.endpoints = []
                ctx.subdomains = []
            except Exception:
                pass
            return stats

        # ── Liveness re-check on primed endpoints (parallel batched HEAD)
        primed_urls = []
        for e in (getattr(ctx, "endpoints", []) or []):
            u = e if isinstance(e, str) else (e.get("url") or e.get("path") or "")
            if u and u.startswith(("http://", "https://")):
                primed_urls.append(u)
        if not primed_urls:
            return stats
        # Cap to avoid excessive traffic on huge intel stores
        MAX_VERIFY = 300
        primed_urls = primed_urls[:MAX_VERIFY]
        sem = _aio.Semaphore(10)
        alive: List[str] = []
        dead: List[str] = []

        async def _check(u):
            async with sem:
                try:
                    rr = await client.head(u, timeout=6)
                    # HEAD sometimes 405 — retry GET
                    if rr.status_code == 405:
                        rr = await client.get(u, timeout=6)
                    if rr.status_code in (404, 410) or 500 <= rr.status_code < 600:
                        dead.append(u)
                    else:
                        alive.append(u)
                except Exception:
                    dead.append(u)

        await _aio.gather(*(_check(u) for u in primed_urls))
        stats["endpoints_dropped"] = len(dead)
        stats["endpoints_kept"] = len(alive)
        # Drop dead endpoints from ctx
        try:
            new_eps = []
            for e in (getattr(ctx, "endpoints", []) or []):
                u = e if isinstance(e, str) else (e.get("url") or e.get("path") or "")
                if u not in dead:
                    new_eps.append(e)
            ctx.endpoints = new_eps
        except Exception:
            pass

    logger.info(f"[TargetMemory] verify: fingerprint_changed={stats['fingerprint_changed']} "
                f"endpoints alive/dead={stats['endpoints_kept']}/{stats['endpoints_dropped']}")
    return stats


def prime_ctx(ctx, target: str) -> Dict[str, Any]:
    """Warm-start a fresh ctx with prior intel — call at scan start.

    Seeds ctx.endpoints/subdomains/technologies with prior known values so
    the crawler starts from what we already know instead of re-discovering."""
    intel = load_intel(target)
    if not intel:
        return {}
    stats = {"loaded": True, "endpoints": 0, "subdomains": 0}
    try:
        if intel.get("known_endpoints"):
            eps = list(intel["known_endpoints"])
            try:
                ctx.add_endpoints(eps, source="target_memory")
            except Exception:
                cur = list(getattr(ctx, "endpoints", []) or [])
                ctx.endpoints = list(dict.fromkeys(cur + eps))
            stats["endpoints"] = len(eps)
        if intel.get("known_subdomains"):
            subs = list(intel["known_subdomains"])
            try:
                ctx.add_subdomains(subs, source="target_memory")
            except Exception:
                cur = list(getattr(ctx, "subdomains", []) or [])
                ctx.subdomains = list(dict.fromkeys(cur + subs))
            stats["subdomains"] = len(subs)
        if intel.get("known_tech"):
            try:
                ctx.technologies = {**(getattr(ctx, "technologies", {}) or {}),
                                     **intel["known_tech"]}
            except Exception:
                pass
        # Expose the working logins so AutoLogin skips discovery
        try:
            ctx.prior_intel = intel
        except Exception:
            pass
        logger.info(f"[TargetMemory] Primed ctx for {target} — "
                    f"{stats['endpoints']} endpoints, {stats['subdomains']} subs from prior scans")
    except Exception as e:
        logger.warning(f"[TargetMemory] prime failed: {e}")
    return stats
