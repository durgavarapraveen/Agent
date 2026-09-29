# Redundancy/coverage hardening — progress

Verification note: per-step checks = `py_compile` + import + targeted unit/smoke.
Full E2E (live scan) needs Docker + authorized target — NOT run per step.

## Tier 1 — anti-silent-miss (DONE, verified)
1. Coverage ledger — `core/orchestration/coverage_ledger.py` (new). Enumerable
   (surface × vuln_class) → CONFIRMED/REFUTED/NOT_RUN/ERROR. Applicable side from
   `SurfaceClassifier.classify(ctx).applicable_classes`; reconciles ctx.vulnerabilities
   (status) + family run-ledger (`brain._coverage_ran`). Wired in central_brain
   REPORTING block; `ctx.update('coverage_ledger', report)`. Unit-tested.
2. Orphan probes — real orphans were `cross_role_replay` + `graphql_ws` (single
   unguarded EXPLOITATION call each; depend on that phase's prereqs so NOT moved to
   ACTIVE_SCANNING). Fix: stamp both sites + finalize safety-net in REPORTING that
   runs any critical probe (cross_role_replay/graphql_ws/expert_probes) not in
   `_coverage_ran`. expert_probes already had early+late guarded calls.
3. OOB fail-loud — folded into ledger: `oob_active` + `oob_degraded_classes`
   (SSRF/RCE/XXE/DNS_REBINDING) flagged + logged loud when no collaborator.

## Tier 2 — second oracles (DONE, verified)
4. SQLi time-based DIFFERENTIAL — `probe_engine._time_blind_sqli` (benign baseline
   vs SLEEP(N), confirm-repeat, delta not absolute; skips already-slow endpoints).
   Wired after boolean-blind in probe_point. NEO_SQLI_SLEEP env (default 5).
5. SSTI OOB — added SSTI to `_OOB_CLASSES` + engine-native payload branch
   (Jinja2/SpEL/Freemarker/Smarty/ERB curl-to-OOB).
6. IDOR/BOLA cross-user content oracle — `AuthorizationOracle.compare` gains
   `peer_body`; idor.py fetches the object-owner's legitimate view (peer_uid) and
   confirms VULNERABLE only when attacker body ≈ owner's AND ≠ attacker's own;
   isolated → REJECTED. Backward-compatible (no peer_body = old heuristic).
7. XSS reflection→DOM execution — `XSSProbe._dom_execute_confirm` (Playwright
   render of exact GET URL; dialog OR document.title canary). CONFIRMED only on
   execution; reflection-only → requires_manual + honest note. Safe no-op w/o
   Playwright. (DOM path not E2E-verified here — no browser in this env.)
8. Corroboration gate — NOT naive downgrade (that's the P1-4 bug). New
   `confirmation_gate.corroboration_gate`: CORS/CSRF/JWT/AUTH_BYPASS need a 2nd
   signal (proof/repro≥2/dom/oob/trusted-tool) else → NEEDS_REVIEW (kept, flagged).

## Tier 3 — new classes (IN PROGRESS)
DONE (verified: compile + unit/smoke; auto-registered in scheduler):
- subdomain takeover — core/exploitation/subdomain_takeover_probe.py (INFRA_CONFIG/J).
  Drives existing takeover_workflow (fingerprint + CNAME = 2-signal) over ctx.subdomains.
- OAuth/OIDC abuse — core/exploitation/oauth_abuse_probe.py (AUTH_SESSION/S).
  redirect_uri bypass (arbitrary/suffix/prefix/@), implicit downgrade, missing-state.
- web cache deception — core/exploitation/web_cache_deception_probe.py (INFRA_CONFIG/S).
  2-signal: authed suffixed URL returns private body, same URL unauth still returns it.
- API shadow endpoints — core/exploitation/api_shadow_probe.py (API/J).
  version-swap + undocumented prefixes; garbage-path control defeats SPA-200.
- RFI — wired into OOB engine (probe_engine _OOB_CLASSES + _oob_payloads) + UPE
  default_classes + dispatcher ENGINE_CLASSES.

DONE (batch 2):
- GraphQL argument injection — graphql_ws_probe._graphql_arg_injection (inject
  SQL/NoSQL into typed resolver args; backend-error signature confirms).
- CSTI — core/exploitation/csti_probe.py (INJECTION/J). Rare-product canary
  {{1337*1337}}; skips if server evaluates (that's SSTI); DOM-confirm to 1787569,
  else NEEDS_REVIEW when framework marker + literal reflected. Safe w/o browser.
- gRPC — core/exploitation/grpc_probe.py (API/S). Reflection ListServices +
  file-descriptor method enum + empty-request unauth-reachability (status-code
  gate). Clean no-op w/o grpcio-reflection. Added grpcio+grpcio-reflection to
  requirements.txt.

Registry now 51 probes; builds clean; all Tier-3 probes registered.

## Tier 4 — discovery (PARTIAL)
DONE (verified: compile + unit/smoke):
- #6 path/header input points — surface_classifier: slug/username segment after a
  collection noun → id_like IDOR point (skips static ext + action words); custom
  x-* headers from captured traffic added to header fuzz-list.
- #5 WebSocket capture — crawler.py both paths (Kali script + host async):
  page.on("websocket") captures handshake→captured_request (Upgrade hdr, so
  websocket_probe finds REAL ws URLs) + frames on ctx.websockets. Shared
  _record_websocket() + ingest of data["websockets"].
- #4 port banner/version — network_discovery._scan_port now grabs a banner
  (HTTP Server: header, or greeting read) → service version in assets + findings.

DONE (batch 2, verified against live kali-pentesting container):
- #2 content+param discovery — core/recon/active_discovery.py run_content_discovery
  (ffuf dir JSONL + arjun -oJ param mining). Wired into web recon lane. ffuf JSONL
  parse confirmed live.
- #3 JS-aware crawl — active_discovery.run_js_crawl (katana -jc -jsonl | jq
  .request.endpoint). VERIFIED LIVE against antigravity-web:8900 (found /api/rag/*,
  shell.php5, asset routes). Wired into web recon lane.
- vhost bruteforce — active_discovery.run_vhost_discovery (ffuf -H 'Host: FUZZ.apex'
  -ac). Wired into infra recon lane. Uses dnsrecon top-5000 wordlist.
- CDN origin unmasking — core/recon/cdn_origin.py run_cdn_origin_unmask (fronting
  detection → origin-hint subs + crt.sh SAN pivot → direct-IP Host-override,
  content-similarity confirm). Wired into infra recon lane. Logic unit-tested;
  needs a CDN-fronted target for E2E.
- #1 auto identity provisioning — self-registration ALREADY created user_a/user_b
  (central_brain._bootstrap_self_registration). Real gap was the SILENT authz skip:
  matrix_engine now fails LOUD (AUTHZ_COVERAGE_UNKNOWN) + surfaces on
  ctx.authz_coverage_unknown → coverage_ledger report. Verified.

Env: ENABLE_ACTIVE_DISCOVERY (default true) gates the Kali recon steps.

## ALL TIERS COMPLETE. Registry 51 probes; every touched file compiles.

## Tier 4 — discovery (TODO)
auto identity provisioning, mandatory content+param discovery, JS-aware crawl,
vhost/CDN/port stubs, WS capture, path/header input points

## Red-team reporting layer (DONE, verified)
core/reporting/redteam_narrative.py (documentation only — NO C2/evasion/phishing/lateral):
- ATT&CK technique tagging per finding (_ATTACK_MAP), objective tracking
  (REDTEAM_OBJECTIVES / ctx.redteam_objectives + achievement heuristic),
  kill-chain narrative (tactic-ordered), purple-team detection-gap checklist,
  timestamped deconfliction summary. Wired in central_brain REPORTING after the
  coverage ledger. Unit-tested; ruff clean.
DECLINED (stated to user): autonomous C2, EDR/AV evasion, phishing send,
autonomous lateral-movement/persistence execution — highest-risk dual-use;
contradicts non-destructive/consent-gated posture; plan assigns these to human
operators. Phase 0 governance artifacts: user said skip.

## Human-in-the-loop on critical tasks (DONE, verified)
Central choke: core/escalation/hitl.py::require_human_approval(kind=...) over the
existing EscalationGate (auto-approve <= AUTO_APPROVE_MAX_RISK=MEDIUM; HIGH/CRITICAL
prompt attended / queue+deny-on-timeout unattended; honors --auto-approve). Exported
from core.escalation. CRITICAL_TASKS registry declares the kinds.
Newly gated (were ungated/inconsistent): account_creation (self-register),
file_upload probe, credential_spray dispatch. Already gated (kept): exploitation
plan, deep-tier exploit, detonation, post-exploit, MSF.
Decisions recorded on ctx.hitl_decisions → surfaced in redteam_narrative deconfliction.
Docs: README safety + DEVELOPER §17 invariant #4 + §19 env. Tests 1977 passed / 0 fail.

## HITL scope decision — critical tasks only (DONE, verified)
Criterion: gate actions that change target state / affect other users / are
irreversible / touch real accounts / execute code / stress availability. Do NOT
gate read-only detection (sqli/xss/idor/ssrf/lfi/cors/jwt/... probing).
Gated CENTRALLY in family_scheduler._run_one via CRITICAL_PROBES:
  business_logic, workflow, race (state_change); mass_assign, file_upload
  (active_write/file_upload); cache_poison, smuggling (shared_side_effect);
  graphql_dos (denial_of_service). Fail-closed on gate error.
Gated in central_brain: account_creation (self-register), credential_spray.
Removed the duplicate per-probe file_upload gate (now central). memory_bomb left
ungated (non-destructive by design). Tests 1977 pass; ruff clean.
