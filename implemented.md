# Scan Forensics & Finding-Triage Methodology
**Target:** `decibyl.ai` (www / app / api / docs)
**Scan:** `www.decibyl.ai_20260923T085627Z_c12701a6`
**Window:** 2026-09-23 14:26:31 → 16:59:26 (~2h33m wall). Watchdog budget was `max_runtime 7200s` (2h), but the **hard cap fired ~33 min late** — the WATCHDOG STOP hit at 9164s elapsed, not 7200s (see Part II §7.5). The soft deadline (95.7% of 7200s) fired on time at 16:21:24, so the clock started at process start; only the hard cap overran.
**Analyst view:** cybersecurity + software-engineering post-mortem of one autonomous run.

---

## 1. How the scanner moved through the domain

Two orchestration phases completed (from `PHASE_COVERAGE`):

| Phase | Required | Ran | Gap |
|---|---|---|---|
| recon | 4 | 4 | — |
| active_scanning | 12 | 11 | `ssl_tls` |

**Movement / kill-chain order observed in the log:**
1. **Seed → DNS/asset expansion.** Started from `www.decibyl.ai`; resolved the estate to **4 in-scope hosts**: `www`, `app`, `api`, `docs`. Cloud-storage permutation guesses (`decibyl.ai-backup.s3…`, etc.) were correctly **DENIED** by `TargetScopeValidator` (out of contract).
2. **Fingerprinting.** `dig`, `nmap`, `whatweb`, `httpx`, `wafw00f`, `sslscan` → identified Next.js/Node front end, nginx, Clerk auth, AWS EC2 (`13.126.69.2`), no WAF.
3. **Crawl / surface mapping.** `katana` crawled **50+ endpoints**; Playwright captured authenticated-style requests; sitemap + `__NEXT_DATA__` + JS bundles mined for routes/params.
4. **Active scanning / injection.** `ffuf` (param/dir), `arjun` (param mining), `nuclei` (templates), `sqlmap` (SQLi), `dalfox` (XSS – **all failed rc=2**, CLI bug), plus ~30 in-house `custom_probe`/`AutoDetect` oracles (SSTI, LFI, CORS, open-redirect, IDOR, proto-pollution, header/method abuse).
5. **Exploitation / confirmation.** Each hypothesis re-run 3× → `FINDING_CONFIRMED (3/3)`.
6. **Correlation / reporting.** `VulnGraph` built **199 nodes / 483 edges**, `ChainDetector` found 10 chains (0 complete), persisted 199 findings.

**Request volume:** ~2,400 HTTP GETs (httpx) + app-layer verbs logged: **234 GET, 39 POST, 13 OPTIONS, 3 PUT, 2 DELETE, 1 PATCH**. Every egress passed the scope/egress gate (`EgressTelemetry ALLOWED`). Auth mode was `session=anonymous` throughout — **the scan was entirely unauthenticated**.

**Data collected:** subdomain/DNS records, TLS config, server/tech versions (nginx, Next.js, Clerk, Sentry), 50+ endpoints, API route catalogue (from docs + sitemap), a widget embed script (`decibyl-widget.js`) with an embedded token, a `?api_key=` on `api.decibyl.ai/v1/bots`, health-endpoint output, client JS bundles (Sentry debug IDs, role strings).

---

## 2. The core defect: "Confirmed" means *reproducible*, not *exploitable*

`FINDING_CONFIRMED: [SEV] … (3/3 attempts succeeded)` is applied to **every** hypothesis that produces a stable response — **including explicit non-findings**:

- `No Injection Vulnerabilities Found (3/3)`
- `No Attack Surface Discovered (3/3)`
- `SSL/TLS Configuration Secure (3/3)`
- `OAuth Provider Bypass Unsuccessful (3/3)`
- `Auth Headers Properly Validated - No Bypass (3/3)`
- `Comprehensive Attack Surface Testing Complete (3/3)`
- `Decibyl.ai Vulnerability Assessment Complete (3/3)`

"3/3 succeeded" only proves the **observation is stable across 3 requests**. It does **not** prove a security-relevant state change occurred. This single conflation is what turns a clean target into a 199-item "vulnerability" list. **Reproducibility ≠ vulnerability ≠ exploitability.** Fixing this is the highest-leverage change (see §5).

---

## 3. Full finding triage (199 nodes → real signal)

**Confirmed exploitable with PoC: 0.** Findings carrying request+response proof: **0.** Everything is heuristic/dispatch-level. Breakdown:

### 3a. NOISE — not vulnerabilities (≈150 of 199)

| Bucket | Count (approx) | Why it's noise |
|---|---|---|
| **Negative/summary findings stamped CONFIRMED** | ~20 | "No X found", "…Complete", "…Mitigated", "…Properly Secured", "…Does Not Exist", "Assessment Complete". Agent narration, not defects. |
| **Documentation pages as "API missing authentication"** | 30 | `docs.decibyl.ai/api-reference/*.html` are static docs describing the API — no API, no auth boundary. Every doc page flagged. |
| **SSTI substring false positives** | 8 | Razor×7 + Freemarker on a **Next.js/Node** app. Razor = .NET; impossible. `"2"`/`"49"` matched incidental HTML digits. *(Fixed this session.)* |
| **SPA-200 / path-normalization FPs** | ~6 | `/.env`, `/.env.local`, `/.env.production`, `/.git/config` → SPA shell (200 HTML, not the file). "Path Traversal `_next/static/../../../api/v1/health`" → Next.js normalizes to the health route, no traversal. "IDOR `/agents/1`" → client route → SPA shell. *(.env/.git fixed this session.)* |
| **Passive fingerprinting as "vulns"** | ~20 | nginx version, Powered-By, EC2 infra, SSL "Secure", DNS TXT, RSS feed, contact email, sitemap, tech-stack version, missing headers ×N. Informational hygiene, not exploitable. |
| **Redundant client-bundle disclosures** | ~10 | 7 separate "Widget …" findings all describe the **same public** `decibyl-widget.js`; Sentry debug IDs and role strings in public JS bundles are by-design public. Collapse to 1 info item. |
| **Empty-target nodes** | 14 | `Information Disclosure @ ` with no URL — junk. |

### 3b. SIGNAL — worth manual verification / exploitation (6–8 items)

Ranked by exploit value. None are proven yet; each needs the stated oracle before it's real.

| # | Finding | Sev (if real) | Verify with | Verdict |
|---|---|---|---|---|
| 1 | **Next.js Middleware Bypass via `X-Middleware-Prefetch`** (`/_next/image`, differential 3/3 different response) | **HIGH** if it reaches a protected route unauth | Send header to an auth-gated route; compare to baseline 302/401. Family of CVE-2025-29927. | **Top lead** |
| 2 | **Secret in URL — `api.decibyl.ai/v1/bots?api_key=…`** | **HIGH** if key is live/privileged | Replay the key on an authenticated call; check if it grants access + appears in logs/referrer. | Strong |
| 3 | **Permissive CORS on `/api/v1/` + `/api/v1/mcp/`** | **MED–HIGH** | Confirm `ACAO` reflects arbitrary `Origin` **and** `ACAC: true` together. MCP = AI-control surface → higher. | Strong |
| 4 | **Open Redirect — `/auth/callback?redirect=`, `/auth/logout?redirect=`** | **LOW alone / HIGH in OAuth chain** | Confirm `Location:` → attacker domain, unvalidated. Token-theft if on OAuth return. | Plausible |
| 5 | **Account Enumeration — `/api/v1/auth/login`** | **LOW–MED** | Differential response/timing valid vs invalid user. | Plausible |
| 6 | **Health endpoint disclosure — `/api/v1/health`** | **LOW–MED** | Inspect body: versions/env/internal hosts? | Plausible |
| 7 | **IDOR/BOLA — `/agents/1`** | **HIGH if real** | Two identities; can A read B's object? Likely SPA shell — verify before trusting. | Suspect |
| 8 | **Reflected XSS — `decibyl-widget.js`, `getting-started.html`** | **LOW** | Reflection in a JS/`.html` static asset ≠ executable HTML XSS. Confirm HTML context + `Content-Type: text/html`. | Likely FP |

**Bottom line:** of 199 reported, ~**3 are genuinely worth an exploitation attempt** (middleware bypass, secret-in-URL, credentialed CORS/MCP), ~4 are secondary/chain-only, the remaining ~192 are noise or informational.

---

## 4. Decision framework — "Does this site have a vulnerability worth exploiting?"

A finding is worth exploiting only if it clears **three gates in order**. Skip any gate → downgrade, don't report as a vuln.

### Gate 1 — Existence (is it a real, security-relevant state change?)
Status code, reflection, or a stable response is **not** proof. Require a **positive oracle** matched to the class:

- **Differential oracle** — payload vs benign control produce a divergence explainable *only* by the vuln (auth bypass, SQLi boolean, middleware skip).
- **Out-of-band (OOB) oracle** — blind SSRF/XSS/SQLi/RCE trigger a callback to your collaborator. No callback = no finding.
- **Execution oracle** — a unique, high-entropy marker is *evaluated*, not echoed (SSTI: random `a*b` → exact 7–8-digit product; RCE: `echo <nonce>`).
- **Content/signature oracle** — the response body carries the asserted artifact (`.env` has `KEY=VALUE`; `.git/config` has `[core]`; private key has `PRIVATE KEY`) — never status alone.
- **Cross-identity oracle** — for IDOR/BOLA/authz, identity A must actually read/modify identity B's object; a 200 on a guessed ID is not enough.

### Gate 2 — Exploitability (can *you* actually trigger impact?)
`worth = impact × reachability × precondition_cost`. Kill it if:
- It sits **behind auth you don't hold** and can't obtain (e.g. "TURN Credentials (Auth Required)").
- It needs **victim interaction you can't stage** (self-XSS, theoretical CSRF with SameSite=Lax).
- It's on a **placeholder/static/by-design-public** asset (docs pages, public embed token, client JS bundle).
- The "traversal/injection" is **normalized/sanitized** by the framework before it reaches anything (Next.js path canonicalization).

### Gate 3 — Impact (is the payoff worth the action?)
Rank on realized consequence, not category label:
**Critical** RCE / auth bypass to privileged data / secret granting live access →
**High** IDOR across tenants / stored XSS in app / SSRF to metadata →
**Medium** reflected XSS / open redirect in OAuth chain / info disclosure with secrets →
**Low** version banners, missing headers, non-secret disclosure →
**Info** hygiene, recon, fingerprinting.

**Only Gate-1-passed + Gate-2-reachable + Medium-or-above is "worth exploiting."** Everything else is a report footnote or discard.

### Triage labels to enforce in the pipeline
`CONFIRMED` (oracle fired + PoC reproduces impact) → `PROBABLE` (oracle fired, no PoC yet) → `INFORMATIONAL` (recon/hygiene) → `NOISE` (negative/summary/FP). Client report = CONFIRMED + PROBABLE only. "Worth exploiting" queue = CONFIRMED with impact ≥ Medium.

---

## 5. Concrete scanner changes to kill the noise (maps buckets → code)

**Already fixed this session:**
- ✅ SSTI random-operand oracle (`core/exploitation/ssti_probe.py`) — kills Razor/Freemarker substring FPs.
- ✅ AutoDetect sensitive-file **body/signature gate** (`core/orchestration/agentic_executor.py`) — kills `.env`/`.git` SPA-200 FPs.
- ✅ dalfox `url --url` builder (`core/tools/tool_router.py`) — XSS scan will actually run.

**Recommended next (by impact):**
1. **Rename the `(3/3)` stamp `REPRODUCIBLE`, not `CONFIRMED`.** Promote to `CONFIRMED` only when a Gate-1 oracle fires. *(Root-cause of §2.)*
2. **Negative/summary suppressor.** Refuse to persist any finding whose title asserts absence/completion/safety ("No … found", "Complete", "Mitigated", "Properly Secured/Validated", "Does Not Exist", "Unsuccessful", "Assessment/Testing Complete"). These are agent narration.
3. **Static-doc / SPA-shell classifier.** If the response is the SPA/doc HTML shell (framework markers, `<!doctype html>` where a data/API artifact was expected), do not emit "API missing auth" / "IDOR" / "traversal". Kills the 30 docs-page FPs + `/agents/1`.
4. **Tech-fingerprint gating.** Don't run/emit engine-specific classes against the wrong stack (no .NET/Razor on Node/Next.js; no PHP probes on a static site).
5. **Asset de-duplication.** Collapse N findings pointing at the same URL/asset into one (7 `widget.js` items → 1).
6. **Empty-target guard.** Never create a finding node with no URL/location (drops the 14 junk nodes).
7. **Framework path-normalization awareness.** Resolve `../` before deciding "traversal"; `_next/static/../../../api/v1/health` == `/api/v1/health` == not traversal.
8. **CORS oracle must require `ACAO`-reflect **and** `ACAC:true` together** before "Permissive CORS" is exploitable-grade.

**Expected effect:** 199 → roughly **8–15 real, ranked findings**, ~3 of them in the "worth exploiting" queue — a ~90–95% noise reduction with no loss of the genuine leads.

---

## 6. One-shot verification of the real leads (operator, authorized scope only)
```bash
# 1 middleware bypass — does the header change an auth-gated route's response?
curl -s -o /dev/null -w "base:%{http_code}\n" https://app.decibyl.ai/api/v1/turn/credentials
curl -s -o /dev/null -w "hdr :%{http_code}\n" -H "X-Middleware-Prefetch: 1" https://app.decibyl.ai/api/v1/turn/credentials
# 3 credentialed CORS on API + MCP
curl -s -D- -o /dev/null -H "Origin: https://evil.com" https://app.decibyl.ai/api/v1/mcp/ | grep -i 'access-control-allow-\(origin\|credentials\)'
# 4 open redirect
curl -s -D- -o /dev/null "https://app.decibyl.ai/auth/logout?redirect=https://attacker.com" | grep -i '^location:'
# 6 health disclosure (body, not status)
curl -s https://app.decibyl.ai/api/v1/health | head -c 400
```
Secret-in-URL (#2) and IDOR (#7): verify with the actual credential / two identities out-of-band — do not paste live secrets into shared tooling.

---
---

# PART II — Deeper log pass (orchestration + silent-breakage forensics)

The §1–6 analysis triaged the *findings*. This pass reads the *run itself* — phase clock, coverage math, and code-level breakages. The headline the first pass missed:

> **The scan never actually attacked. It spent ~75% of its life in RECON, entered ACTIVE_SCANNING only in its last ~34 minutes, reached EXPLOITATION ~1 second before the hard watchdog stop (no exploit ran), and executed 3 of 85,926 "applicable" tests before it was killed. The 199 "findings" are almost entirely recon narration — active scanning barely ran.**

## 7. Phase clock — the real timeline (from `BRAIN_PHASE_TRANSITION` / `ENTERING MAIN PHASE`)

| Wall time | Phase | Duration | Note |
|---|---|---|---|
| 14:26:43 | BUSINESS_UNDERSTANDING #1 | 32 s | ok |
| 14:27:15 | **RECON #1** | **~114 min** | OSINT(14:50) → LIVE SUBDOMAIN(15:23) → HTTP INTERCEPT/JS RECON(16:20). Dominated the run. |
| 16:21:23 | transition → ACTIVE_SCANNING… | — | **but next line enters REPORTING (see Bug B)** |
| 16:21:25 | REPORTING #1 (watchdog-soft) | ~4 min | soft-deadline finalize |
| 16:25:36 | **ACTIVE_SCANNING #1** | ~34 min | first & only real active window |
| 16:59:14 | EXPLOITATION | **~1 s** | entered, hard-killed 16:59:15 before any exploit ran |
| 16:59:15 | `WATCHDOG STOP` (hard) | — | fired at **9164s — ~33 min past the 7200s cap**; reporting/persist then ran to 16:59:26; 199 persisted |

**7.1 — Phase budget is inverted (P0).** RECON ate ~114 of ~153 min (~75%). ACTIVE_SCANNING got one 34-min window; EXPLOITATION got ~1 second. A pentest orchestrator should cap recon (it is bounded work on a 4-host estate) and spend the budget on active scanning + exploitation. There is no per-phase time budget / recon deadline — recon ran until the *global* watchdog forced the issue. **Fix:** add a per-phase soft cap (e.g. RECON ≤ 25–30% of `max_runtime`) that force-advances to ACTIVE_SCANNING, independent of coverage. (Same class as the earlier "phase loop fix" no-progress guard, but here the stall is a *budget* stall, not a convergence stall.)

**7.2 — Soft-deadline REPORTING finalize is defeated (P0, Bug B).** At 16:21:24 `CRITICAL WATCHDOG SOFT: soft deadline 96% of budget — finalizing via REPORTING`, it flushed 164 findings and entered REPORTING. **Then at 16:25:34 the planner transitioned REPORTING → ACTIVE_SCANNING and kept scanning for 34 more minutes** until the hard kill. The graceful finalize did nothing — REPORTING is not "sticky." Root cause: the coverage-driven planner re-evaluates and, seeing coverage 0% < 85% target, re-enters an earlier phase, overriding the watchdog's finalize intent. **Fix:** once the watchdog soft-deadline routes to REPORTING, latch a `finalizing` flag that the phase planner must honor (no transition *out* of REPORTING except to terminal). This is the sibling of §8.

**7.3 — Transition/enter mismatch (Bug C).** `BRAIN_PHASE_TRANSITION: RECON -> ACTIVE_SCANNING` (16:21:23) is immediately followed by `ENTERING MAIN PHASE: REPORTING` (16:21:25). The transition *decision* and the phase *entered* disagree because the watchdog interrupt races the planner. Log/behaviour are inconsistent — hard to audit. **Fix:** single source of truth for "next phase"; watchdog should set it *before* the transition log, not after.

**7.4 — sqlmap serially blocked recon for 9m40s.** One `sqlmap -u …` invocation (14:40:24 → 14:50:04, `steps=1`) stalled the whole recon agent wall-clock. Long-running tools inside a serial agent loop should run under the bounded-concurrency fan-out (memory: "Parallel fan-out") or a tighter per-tool timeout, not block the phase.

**7.5 — Hard watchdog overran its own 7200s cap by ~33 min (P0, new).** The math is unambiguous: the soft deadline logged `95.7% of budget` at 16:21:24 → the 7200s clock started at process start (14:26:31). So the 100% hard cap was due at ~16:26:31, but `WATCHDOG STOP: max_runtime 7200.0s reached` did not fire until **16:59:15 — 9164s elapsed, 127% of the 7200s budget**. The hard cap is not enforced promptly: it is checked cooperatively between phase-loop iterations, and the REPORTING→ACTIVE_SCANNING bounce (§7.2) re-entered a long active-scan window (16:25:36→16:59:15) during which the hard check evidently did not evaluate (or was reset by the phase transition). Net effect: the run consumed ~2h33m against a 2h budget. **Fix:** evaluate the hard `max_runtime` on a monotonic wall-clock timer independent of the phase loop (or check it at every tool-call boundary, not only per phase-iteration), and never let a phase transition reset it. This compounds §7.2 — both the *graceful* finalize and the *hard* stop failed to bound the run.

## 8. Root cause of "never converges": coverage denominator explosion (P0)

```
16:21  COVERAGE_REAL: applicable=85925 executed=0   (0.0%)  85925 unaddressed gaps
16:25  COVERAGE_REAL: applicable=85926 executed=3   (0.0%)  resolved=3
16:59  COVERAGE_REAL: applicable=85926 executed=3   (0.0%)  ← end of run
CompletionValidator: 'Coverage 0.0% below minimum 85.0%'  → refuses to complete
```

The applicability engine expanded to **85,926 "applicable" test units** (endpoint × catalog cross-product: `ep-28:bizlogic_price_llm_01`, `ep-28:sca_manifest_exposed_01`, `ep-28:dns_takeover_01`, …). With only 3 ever executed, coverage is pinned at 0.0% **for the entire run**. Because `CompletionValidator` needs ≥85%, completion is **mathematically unreachable**, so the scan can never converge and only stops at the hard 7200s watchdog. This is the *engine* behind the §7 phase imbalance: the planner keeps chasing an 85% target against an 85,926 denominator.

This is the same "denominator explosion" class noted before (memory: batch-2 `55k→real`, batch-3 `COVERAGE_STRICT_APPLICABILITY`), **still not contained** — it regressed to 85,926. **Fixes:**
1. Cap/normalize the applicability denominator to *reachable* units (apply `COVERAGE_STRICT_APPLICABILITY` here — a 4-host mostly-static estate cannot have 85,926 applicable tests).
2. Make `CompletionValidator` converge on *diminishing returns / budget*, not only on an absolute % that an inflated denominator makes unreachable. "0 new findings in N iterations" or "phase budget spent" must be able to complete a run.
3. `executed=3` after a 34-min active window is itself alarming → see §9.

## 9. Silent functional breakages (findings-suppressors & tool-breakers)

These are code bugs that ran quietly the whole scan. They are the reason `executed=3` and why active scanning produced no real signal.

**9.1 — Critic confirmation gate throws 164× (P0).** `[Critic] verdict exception: CriticAgent._check_confirmation_gate() missing 1 required positional argument: 'ftype'` — every critic verdict raised. The confirmation/critic gate is **entirely non-functional** across the run (caught by a broad except, so it fails open/closed silently). Same signature as the earlier systemic `llm.generate()` suppressor (memory: `llm_generate_method_bug`). **Fix:** pass `ftype` at the call site (or make it keyword-optional); add a unit test that calls the gate with a real finding.

**9.2 — ToolSanitize strips *required* tool flags (P0).** The sanitizer allowlist removed target/essential flags:
- `-u` stripped for **sqlmap**, **nuclei**, ffuf → tools ran with no target URL.
- `-severity`, `-tags`, `-silent`, `-t`(templates) stripped for **nuclei** → `[FTL] no templates provided for scan`.
- `-aff`, `-c`, `-depth`, `-o` stripped for **katana**.

Result: **nuclei and sqlmap were effectively no-ops** from the stripped `-u`/`-t`/`-severity` flags above; **dalfox** was already dead from the separate Part I §5 `--url` builder bug (its failures are `--url not provided` / `rc=2`, a command-construction issue, not a ToolSanitize strip). Either way, XSS + template + SQLi coverage was **zero for tool reasons, not target reasons**. **Fix:** the ToolSanitize allowlist must whitelist each tool's mandatory flags (`-u`, `-t`, `-severity` for nuclei; `-u` for sqlmap), and the dalfox `--url` builder fix must land upstream of the sanitizer so a correctly-built command is not re-broken.

**9.3 — Policy "fresh result already recorded" blocks re-execution (P1).** ~100× `[POLICY] DENY action=authorize_tool … reason=fresh result already recorded` / `[CONTRACT] rule=policy.authorize_tool passed=False`. The idempotency guard is denying tool authorization against targets that were only *recon*-touched, starving ACTIVE_SCANNING (`executed=3`). **Fix:** scope the "fresh result" cache by (tool, target, **operation/phase**) so a recon HEAD doesn't satisfy an active-scan probe; expire per phase.

**9.4 — Enterprise report generation crashed (P1).** `Enterprise report generation failed: 'NormalizedLLMResponse' object has no attribute 'replace'` — the report writer called `.replace()` on the response object instead of its `.text`/`.content`. **The run produced no enterprise report.** Same normalized-response-object footgun as the gateway/`.generate()` bugs. **Fix:** use the accessor (`resp.text`) and add a type guard.

**9.5 — Malformed tool commands (P2).** `curl: option --HEAD is unknown` (should be `-I`/`--head`), `curl: No closing quotation`, `arjun` usage error. Command builders emit invalid syntax for curl/arjun. Low individual impact but they burn iterations and pollute the error log.

## 10. Data-quality, scope & correctness notes

**10.1 — Real backend `api.decibyl.com` blocked 32× (P1).** `EgressFirewall BLOCKED egress to api.decibyl.com` (12×) + `TargetScopeValidator DENIED host=api.decibyl.com` (20×). The health endpoint's own body advertises `backend_api_endpoint: https://api.decibyl.ai`, but the estate also references `api.decibyl.com` — the actual API backend — which is out-of-contract and never probed. Matches the earlier "OOS discovery drop" work; the `_related_to_scope` surfacing should catch this, verify it did (it should appear in the Coverage/OOS panel, not just be silently denied).

**10.2 — Auth-provider contradiction (correctness).** Finding at 16:20 asserts *"protected by Clerk auth"*, but `/api/v1/health` body self-reports `"auth_provider":"local"`, `"deployment_mode":"oss"`, `"signup_enabled":true`. The fingerprint (Clerk) contradicts ground truth (local). An OSS/local-auth app with `signup_enabled:true` is a *different, more attackable* target than a Clerk-gated SaaS — the scanner mis-modeled the auth surface and never used `signup_enabled` to self-register (the memory `AUTH_SELF_REGISTER` path). **Action:** trust structured health/config output over heuristic fingerprints; feed `signup_enabled:true` into the self-register identity bootstrap.

**10.3 — Health endpoint disclosure is real signal, and it was logged twice (P2).** `/api/v1/health` → 200 with `version:1.42.0`, `backend_api_endpoint`, `deployment_mode:oss`, `auth_provider:local`, feature flags. This upgrades §3b #6 from "Plausible" to **confirmed low/med info-disclosure with body evidence** — the one active finding that actually cleared a content oracle. It was emitted as two separate findings (15:31 and 15:50) → dedup gap.

**10.4 — Google-Fonts egress denied 871× (P3 noise).** `DENIED host=fonts.googleapis.com` (653) + `fonts.gstatic.com` (218) = 871 warnings from the crawler re-requesting font CDNs. Dedupe denied hosts (deny once, cache) — this is 50% of all WARNING volume and buries real signal.

**10.5 — Jev "novel surface — no known family fits" 12× (P2).** On this `implementing-jev` branch, the Jev classifier fails to map `docs.decibyl.ai` telephony/integration pages to any family, so they fall through untested. Add a default/generic family or a "novel-surface" queue so unclassified surfaces still get baseline probes instead of being dropped.

## 11. Prioritized fix backlog (this run's evidence)

| # | Fix | Sev | Evidence |
|---|---|---|---|
| 1 | Cap applicability denominator + let CompletionValidator finish on budget/diminishing-returns (not only 85%) | **P0** | `applicable=85926 executed=3 0.0%` → never converges |
| 2 | Per-phase time budget; force-advance RECON→ACTIVE_SCANNING at ~25–30% | **P0** | RECON ~114 min (~75%) / EXPLOITATION ~1 s |
| 3 | Latch REPORTING on watchdog-soft finalize (no bounce back to ACTIVE_SCANNING) | **P0** | REPORTING→ACTIVE_SCANNING at 16:25 after soft deadline |
| 3b | Enforce hard `max_runtime` on a monotonic timer / per-tool-call, never reset by a phase transition | **P0** | hard stop fired at 9164s = 127% of 7200s cap (§7.5) |
| 4 | Fix `CriticAgent._check_confirmation_gate(ftype=…)` + test | **P0** | 164× verdict exceptions |
| 5 | ToolSanitize: whitelist mandatory flags (`-u`,`-t`,`-severity`,`--url`) | **P0** | nuclei/sqlmap/dalfox neutered |
| 6 | Scope "fresh result" policy by (tool,target,phase); expire per phase | **P1** | ~100 authorize_tool DENYs, executed=3 |
| 7 | Enterprise report: use `resp.text`, add type guard | **P1** | `NormalizedLLMResponse has no attribute 'replace'` |
| 8 | Trust health/config over fingerprint; wire `signup_enabled` → self-register | **P1** | Clerk vs `auth_provider:local` |
| 9 | Bound long tools (sqlmap) under fan-out / tighter timeout | **P2** | 9m40s serial recon block |
| 10 | Dedup findings (health ×2) + dedup denied-host log spam (fonts ×871) | **P2/P3** | duplicate health finding; 871 font DENYs |
| 11 | Jev novel-surface fallback family | **P2** | 12× "no known family fits" |
| 12 | Fix curl/arjun command builders (`-I` not `--HEAD`, quoting) | **P3** | curl/arjun syntax errors |

**Reconciliation with Part I:** §1 credited "11 active tools ran" — the log shows the tools *dispatched* but were largely neutralized by ToolSanitize (§9.2) and policy DENY (§9.3), producing `executed=3`. So even the "signal" leads in §3b were never actively tested; they remain **hypotheses from recon**, not results. The single active finding that cleared a real oracle is the health-endpoint disclosure (§10.3). Everything else awaits the fixes above before a re-run can produce trustworthy coverage.

---

## 12. Fixes applied this session (via implement→review→fix loop)

Each change was gated (py_compile + ruff + targeted runtime/AST checks) and passed an independent reviewer-agent pass before being accepted.

| §11 # | Fix | Status | File |
|---|---|---|---|
| 4 | **Critic confirmation gate** — `_check_confirmation_gate` was `@staticmethod` with a stray `self` param → mis-bound args, threw 164×/run, silently disabling the critic. Removed the `self` param. | ✅ **DONE** | [critic_agent.py:236](core/verification/critic_agent.py:236) |
| 4b | **Same defect class, 2nd instance** (found by the reviewer) — `_is_spa_false_positive` was defined with neither `self` nor `@staticmethod` but called via `self.` → `TypeError` on every `verify_finding`. Made it `@staticmethod`. An AST mis-bind sweep now guards this class mechanically. | ✅ **DONE** | [critic_agent.py:261](core/verification/critic_agent.py:261) |
| 5 | **ToolSanitize stripped target flags** — allowlist dropped `-u`/`-t`/`-severity`/`--url` etc., neutering nuclei/sqlmap/ffuf/katana. Added per-tool scan-control flags + a shared `_TARGET_FLAGS` set unioned into every allowlist. Security control preserved (no file-write/shell/exec flags added; target still scope-validated upstream). | ✅ **DONE** | [agentic_executor.py:917](core/orchestration/agentic_executor.py:917) |
| 7 | **Enterprise report crash** — `generate_response()` returns a `NormalizedLLMResponse`; the exec-summary was passed as-is into the report + `reporter.generate()`, which called `.replace()` on the object. Extract `.content` (defensive). Report now generates. | ✅ **DONE** | [central_brain.py:9325](core/orchestration/central_brain.py:9325) |
| 3 (§7.2) | **REPORTING bounce** — after the soft-deadline routed to REPORTING, the DAG scheduler saw the skipped scan phases as incomplete and re-entered ACTIVE_SCANNING. Added a **FINALIZE LATCH** in `_transition_to_next_phase`: once winding down, run REPORTING once then terminate (`current_phase=None`), taking precedence over the scheduler. | ✅ **DONE** | [central_brain.py:735](core/orchestration/central_brain.py:735) |
| 3b (§7.5) | **Hard-cap overrun (9164s vs 7200s)** — largely resolved by the §7.2 latch (no re-entry into the 34-min ACTIVE window). Also hardened the watchdog to a **monotonic clock** (immune to wall-clock steps over a 2h run). | ✅ **DONE** | [watchdog.py:76](core/security/watchdog.py:76) |
| 1 (§8) | **Never-converges → completion honesty** — the live `ConvergenceEngineV2` has no `get_state()`, so CompletionValidator's stall check was dead code and it could never pass (0% < 85% forever). Now uses V2's `get_stall_status()`; a genuine 10-min no-progress stall is a valid **diminishing-returns** completion (strict %-mode via `COVERAGE_STRICT_COMPLETION=1`). | ✅ **DONE** | [completion_validator.py:14](core/convergence/completion_validator.py:14) |
| 6 | **Fresh-result DENY starved active scanning (`executed=3`)** — the dedup key was host-level `(target, operation)`, so one tool's fresh result suppressed every later probe with the same operation on that host. Scoped the freshness key by **tool_id** at all 3 lockstep sites (record + 2 reads). Monotonic: a finer key can only allow more runs, never deny more. Same-tool dedup preserved. | ✅ **DONE** | [tool_gateway.py:119](core/tools/tool_gateway.py:119), [policy_engine.py:120](core/decisions/policy_engine.py:120) |
| 10 | **Log spam — 871 identical `DENIED host=fonts.googleapis.com` warnings** (half of all warnings). De-dupe: log each unique denied host once at WARNING, repeats at DEBUG. Deny decision unchanged. | ✅ **DONE** | [authorization.py:271](core/security/authorization.py:271) |

**§8 denominator — root cause traced, fix deferred (needs labeled corpus).** The applicability guard *is* wired ([central_brain.py:1978](core/orchestration/central_brain.py:1978) passes `applicable=`), so 85,926 is not a missing-guard bug — it is **over-classification**: `classify_applicability` ([applicability_engine.py:39](core/coverage/applicability_engine.py:39)) only marks input-dependent classes (injection/xss/…) NOT_APPLICABLE on param-less GETs; host-level tests (missing-HSTS, clickjacking, TLS, info-headers) are counted once **per endpoint** instead of once per host, so ~200 tests × ~430 endpoints ≈ 86k. Fixing this means catalog metadata (host-level vs endpoint-level scope) + validation against a labeled corpus and a live/replay run — not a blind predicate tweak, which risks *hiding* real gaps. The §8 completion fix above makes the run terminate cleanly despite the inflated denominator; the denominator itself is the remaining accuracy work.

**Still deferred (need a live/replay scan as the gate, not a static edit).** §11 items 2 (§7.1 per-phase RECON budget — RECON's 114-min sub-pipeline runs between watchdog checks; needs a checkpoint injected into the recon pipeline), 8 (fingerprint-vs-health auth trust + self-register), 9 (sqlmap serial-block timeout — a config value but its effect is only observable live), 11 (Jev novel-surface fallback), plus the §8 denominator accuracy above.

**Reclassified after investigation:**
- **#12 (curl/arjun "command builder" bugs)** — NOT a builder bug. The hardcoded curl builder ([tool_adapter.py:627](core/tools/tool_adapter.py:627)) correctly uses `-I`. The `curl --HEAD` / "No closing quotation" errors are **LLM-emitted commands**, i.e. command-hygiene of model output, not a code defect. Fixing it means validating/repairing model-generated shell commands — a separate, fuzzier workstream best driven by a live trace of the exact malformed commands.

Recommended: re-run scan `c12701a6` with the **9 fixes now applied**, confirm the critic fires, `executed` ≫ 3, a report is produced, the run finalizes without a hard-cap overrun, and active scanning is no longer starved by fresh-result denials — then tackle the remaining set with the live run as the objective gate.
