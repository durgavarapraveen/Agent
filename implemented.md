# Scan Forensics & Finding-Triage Methodology
**Target:** `decibyl.ai` (www / app / api / docs)
**Scan:** `www.decibyl.ai_20260923T085627Z_c12701a6`
**Window:** 2026-09-23 14:26:31 → 16:59:26 (~2h33m, stopped by watchdog `max_runtime 7200s`)
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
