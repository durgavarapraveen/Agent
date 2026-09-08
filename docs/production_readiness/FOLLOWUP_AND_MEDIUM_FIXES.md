# FOLLOW-UP + MEDIUM FIXES APPLIED — 2026-09-06

Covers the four "next actions" from `HIGH_FIXES_APPLIED.md` and the first pass on MEDIUM issues from `RISK_MATRIX.md`.

## 1. Follow-up items (done)

### Frontend now authenticates
- **`ui/web/src/api.js`** fully rewritten:
  - Sends `X-API-Key` header on every request (from `window.__ANTIGRAVITY_API_KEY__`, `localStorage["ag_api_key"]`, or a one-time `?api_key=…` URL param that is auto-migrated to storage and stripped from the address bar).
  - WebSocket handshake uses `Sec-WebSocket-Protocol: api-key,<key>` — matches the backend at `ui/api/server.py:ws_scan_feed`. On close code 4401 the client stops retrying and dispatches a `ag:unauthorized` event.
  - New `createPoller(fetchFn, onData, ms)` helper that uses `AbortController` + a monotonic generation counter — closes the WS-vs-poll race (#087).
  - Duplicate `getAttackChains` / `getReviewQueue` / `getExploitReports` object keys removed (#088).
  - Download URLs (`getReportUrl`, `getSarifUrl`, `getEvidenceUrl`, `scanArtifactUrl`, `getScanLogsDownloadUrl`) append the API key as a query param because browsers can't set headers on top-level navigations.
  - Exports `getApiKey`, `setApiKey`, `clearApiKey` for use by Settings.
- **`ui/web/src/App.jsx`**: added an `AuthBanner` that listens for `ag:unauthorized` events and prompts the operator to open Settings.
- **`ui/web/src/pages/Settings.jsx`**: added an API-Key input (password-masked with reveal toggle), Save/Clear buttons, and a live probe of the API on save.
- Verified the frontend builds clean: `vite build` succeeds; 45 modules transformed.

### `slowapi` added to requirements
- **`requirements.txt`**: `slowapi>=0.1.9` with a comment explaining the fallback path (built-in per-route limiter still runs if slowapi is missing).

### `FP_MODEL_MIN_ROWS` documented
- **`.env.example`**: added an "FP_MODEL_MIN_ROWS" entry with the default (200) and pointer to `core/reporting/fp_filter.py` for the CSV schema.

### Kali base digest — helper script
Docker image resolution can't be run from inside this sandbox, so the digest is left as a build-arg. The pinning workflow is now scripted:
- **`scripts/pin_kali_digest.sh`**: pulls `kalilinux/kali-rolling`, resolves its digest via `docker inspect`, and either rewrites `ARG KALI_ROLLING_DIGEST=` in `Dockerfile` (default) or checks whether it's stale (`--check`, suitable for CI).

Run once locally, commit the resulting `Dockerfile` change:
```bash
./scripts/pin_kali_digest.sh
git diff Dockerfile
git add Dockerfile && git commit -m "chore: pin Kali base digest"
```

## 2. MEDIUM fixes applied (this pass)

Numbers reference `ALL_ISSUES.md` and `RISK_MATRIX.md`.

### Scope enforcement (#079, #080, #081)
- **`core/scope/manager.py`**:
  - New static `_normalize_host` — lowercases, strips trailing dot, IDN/punycode-converts, strips IPv6 brackets. Applied at every entry point.
  - `_is_ip_allowed` no longer uses a bare `except:` — logs at `DEBUG` when the input isn't an IP literal (misrouting is diagnosable), and at `WARNING` when a configured CIDR is malformed (previously swallowed silently).
  - `validate_url` uses `urlparse.hostname` (which already strips IPv6 brackets and ports), then routes IP literals to the IP allowlist. No more `split(":")[0]` that mangles `[2001:db8::1]:8080`.
  - `validate_plan` rewritten the same way — synthetic `http://` scheme prepended when the caller passed a bare host, then a single normalized path handles both URL and bare-host inputs.

### Duplicate route registration (#089)
- **`ui/api/server.py`**: the second registration of `GET /api/scans/{scan_id}/attack-chains` (returning a different shape than the frontend expected) removed. The earlier handler at ~line 1110 (`{scan_id, count, chains}` shape) is now the only one.

### Reporting quality (#102, #103, #105)
- **`core/reporting/reporting.py`** `add_osint_findings`: replaced `str.replace('</main>', ...)` with an `rfind('</main>')` + slice, so a finding whose proof block quotes `</main>` no longer corrupts the report layout.
- **`core/reporting/fp_filter.py`** `NON_HTML_CONTENT_TYPES`: removed `application/javascript` and `image/svg+xml` — both are executable-in-context (JSONP-XSS, SVG-embedded script) and the previous FP filter was silently suppressing real findings.
- **`core/reporting/sarif_export.py`** `_make_fingerprint`: return full 64-char SHA-256 hex instead of a 32-char truncation. Truncation invited collisions on large scans and broke SARIF partial-fingerprint equality semantics.

### Persistence (#P2-15 attack chains, #112 missing indexes, #P2-1 probe silent failures)
- **`core/database/pg_store.py`**:
  - `attack_chains`: new partial unique index `ux_attack_chains_scan_chain (scan_id, chain_id) WHERE chain_id <> ''` (additive migration).
  - `AttackChainRepo.bulk_upsert`: now uses `execute_values` + `ON CONFLICT (scan_id, chain_id) WHERE chain_id <> '' DO UPDATE`. Previously the `ON CONFLICT DO NOTHING` without a target would raise on the real conflict.
  - Hot-path indexes added (all `IF NOT EXISTS`): `audit_log.timestamp`, `execution_audit.timestamp`, `findings_dedup.last_seen`, `scans.started_at`, `experiences.test_type`, `experiences.created_at`, `llm_failures.created_at`, `strategies.test_type`.
- **`core/execution/executors/generic.py`** `_probe`:
  - Network errors (`URLError`, `TimeoutError`, `ConnectionError`, `OSError`) now log at `WARNING` — no more silent `(0, "", {})` that was indistinguishable from a real empty response.
  - Truly unexpected exceptions use `logger.exception` for a stack trace.

### Container-exec hygiene (#P2-4)
- **`core/execution/executors/generic.py`** `_run_in_kali`:
  - Container name validated against Docker's own naming regex (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`) before use.
  - Switched from `subprocess.run(shell=True, cmd_string)` to `subprocess.run(argv, shell=False)`. The base64 payload alphabet cannot contain shell metacharacters, and the outer shell layer is now gone.
  - Explicit `TimeoutExpired` and `FileNotFoundError` handling with meaningful error messages.

## New env vars

| Var | Purpose | Default |
|---|---|---|
| `ANTIGRAVITY_ENV` | dev/production runtime mode gate | `development` |
| `THREAT_INTEL_INSECURE_TLS` | 1 = disable TLS verify on threat feeds | unset (verified) |
| `RAG_INGEST_ROOTS` | Semicolon-separated allowlist for `/api/rag/ingest/file` | `data/rag_ingest` |
| `FP_MODEL_MIN_ROWS` | Min labelled rows before ML FP filter trains | 200 |
| `ENCRYPTION_KEY_DEV_UNSAFE` | 1 = allow dev-only auto-generated encryption key | unset |

All documented in `.env.example`.

## Files changed

| File | Purpose |
|---|---|
| `ui/web/src/api.js` | X-API-Key + WS subprotocol + `createPoller` + dedup keys |
| `ui/web/src/App.jsx` | Global `ag:unauthorized` banner |
| `ui/web/src/pages/Settings.jsx` | API-key management UI |
| `requirements.txt` | `slowapi>=0.1.9` |
| `.env.example` | 5 new documented env vars |
| `scripts/pin_kali_digest.sh` | Docker base digest pinning helper |
| `Dockerfile` | (previously HIGH — refers to script) |
| `core/scope/manager.py` | IDN/trailing-dot/IPv6/case normalization + malformed-CIDR warnings |
| `core/reporting/reporting.py` | Safe `</main>` injection via rfind + slice |
| `core/reporting/fp_filter.py` | Removed `application/javascript` and `image/svg+xml` from FP list |
| `core/reporting/sarif_export.py` | Full 64-char SARIF fingerprint |
| `core/database/pg_store.py` | AttackChains `ON CONFLICT` fixed; 8 hot-path indexes added |
| `core/execution/executors/generic.py` | `_probe` logs WARN on network error; `_run_in_kali` shell-hardened |
| `ui/api/server.py` | Duplicate `/attack-chains` route removed |

## Verification

```bash
cd C:/Users/durga/Desktop/Projects/outputs
python -m py_compile \
  core/scope/manager.py \
  core/reporting/reporting.py core/reporting/fp_filter.py core/reporting/sarif_export.py \
  core/database/pg_store.py \
  core/execution/executors/generic.py \
  ui/api/server.py
# All clean.

cd ui/web && ./node_modules/.bin/vite build
# ✓ 45 modules transformed. Built in <500ms.
```

## Cumulative status

- CRITICAL (26): **26/26 closed** ✓
- HIGH (34): **34/34 addressed** ✓
- MEDIUM: **13 addressed** in this pass; **~21 remaining** (mostly frontend polling hygiene, scope-validator consolidation, and the remaining N+1 sites).
- LOW (46): pending
- INFO (16): pending

## Remaining MEDIUM (call out for next pass)

Straightforward remaining P2 items from `RISK_MATRIX.md`:

- **#082/#083**: consolidate `ScopeManager` + `TargetScopeValidator` + `LegalValidator` into one repo-of-record.
- **#087**: migrate the frontend polling call sites (`LiveScan.jsx`, `Dashboard.jsx`, `Targets.jsx`, `Analytics.jsx`, `LiveAgentsPanel.jsx`, `AccessGainedPanel.jsx`, `ArtifactsPanel.jsx`, `ActivityLog.jsx`) to the new `createPoller()` helper. This turns the WS+poll race off in each page.
- **#090**: replace `.catch(()=>{})` in each page with a per-page error banner state; the auth path already dispatches `ag:unauthorized`, but network/500 errors are still invisible.
- **#091**: broader silent-failure sweep in `generic.py` (per-payload `_probe` returns already logged; other executors need the same treatment).
- **#094**: `xss.py` — replace naive `payload in body` substring with an HTML-context-aware check.
- **#096**: `authentication.py` — response-body content check (not just `status < 400`) before flagging login as success.
- **#097**: DB dedup transactionality (add `SAVEPOINT` around each finding write so one bad row can't abort the whole batch).
- **#101**: `bootstrap_recover()` sweeper that marks orphaned "running" scans failed on API startup.
- **#106**: `scan_id` sanitization at the reporting path (`reporting_engine.py:55`).

These are all self-contained and low-risk; the biggest is #087 (touches ~8 React files).
