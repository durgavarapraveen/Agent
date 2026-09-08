# MEDIUM FIXES COMPLETE — 2026-09-06

Closes the remaining **~21 MEDIUM issues** from `ALL_ISSUES.md` and the five call-outs in `FOLLOWUP_AND_MEDIUM_FIXES.md`. All Python files compile; UI builds clean (45 modules, ~2s).

## Files changed

| # | File | Purpose |
|---|---|---|
| 1 | `core/database/pg_store.py` | `ScanRepo.bootstrap_recover()`, per-row SAVEPOINT fallback in `VulnRepo.bulk_insert`, `list_all(limit, offset)` on 5 repos |
| 2 | `ui/api/server.py` | `bootstrap_recover()` wired at startup |
| 3 | **NEW** `core/security/scope_facade.py` | Single `ScopeAuthority` façade over `ScopeManager` + `TargetScopeValidator` + `LegalValidator` |
| 4 | `core/execution/execution_pipeline.py` | Prefers `ScopeAuthority.is_authorized()` before falling back to legacy |
| 5 | `core/orchestration/central_brain.py` | Wires `TargetScopeValidator` into the façade + seeds allowlist |
| 6 | `core/execution/executors/xss.py` | `_classify_reflection()` — HTML/attribute/JS-string/JSON/textarea context awareness |
| 7 | `core/execution/executors/authentication.py` | `_classify_login_response()` — reject / success / inconclusive with content markers, not just status code |
| 8 | `core/validation/dedup.py` | Never suppress recurring HIGH/CRITICAL findings |
| 9 | `core/reporting/reporting_engine.py` | `scan_id` sanitized + resolve-boundary check before writing artefacts |
| 10 | `core/reporting/retest_engine.py` | `BASELINE_FILE`/`REGRESSION_REPORT_FILE` anchored to `data/retest/` (overridable via env) |
| 11 | `core/reporting/reporting.py` | POC curl commands built with `shlex.quote()` — no shell injection when the operator pastes them |
| 12 | `core/reporting/report_builder.py` | CDN scripts loaded with `crossorigin` + `defer` + noscript fallback banner; PDF-fallback writes to `.html` not `.pdf` |
| 13 | `core/orchestration/central_brain_mixins/finding_ingestion.py` | Duplicate `"hidden"` dict key removed — no more silent HIGH→MEDIUM downgrade |
| 14 | `core/security/consent.py` | `AUTO_APPROVE_EXPLOITS=1` refused in production |
| 15 | `core/intelligence/censys_client.py` | Graceful empty-result on missing PAT; wired to provider gate |
| 16 | **NEW** `core/intelligence/_provider_gate.py` | Per-provider rate limit + circuit breaker |
| 17 | `ui/web/src/pages/Dashboard.jsx` | 2 polling sites → `createPoller` |
| 18 | `ui/web/src/pages/Targets.jsx` | 1 site → `createPoller` |
| 19 | `ui/web/src/pages/LiveScan.jsx` | 3 sites → `createPoller` (top-level, per-scan REST fallback, HealthIndicator) |
| 20 | `ui/web/src/components/LiveAgentsPanel.jsx` | 2 sites → `createPoller` |
| 21 | `ui/web/src/components/AccessGainedPanel.jsx` | → `createPoller` |
| 22 | `ui/web/src/components/ArtifactsPanel.jsx` | → `createPoller` |
| 23 | `ui/web/src/components/ActivityLog.jsx` | → `createPoller` |

## Fixes by issue ID

### Persistence
- **#097** `VulnRepo.bulk_insert`: on batch failure the code falls back to per-row inserts guarded by `SAVEPOINT sp_vuln`, so one bad row (oversized JSONB, encoding issue) can no longer take down the rest of the batch.
- **#098/#101** `ScanRepo.bootstrap_recover()`: called from `ui/api/server.py` at import time. Reconciles any scan row left in `running/starting/stopping` whose child process is gone → marks it `failed` with a clear `error` value. Best-effort — never raises.
- **#113** Pagination on 5 unbounded `list_all()` sites (`TargetRepo`, `ScanRepo`, `FindingV2Repo`, `ScheduleRepo`, `CampaignRepo`) — each accepts `limit`/`offset` with a hard upper bound.

### Scope enforcement
- **#082/#083** `ScopeAuthority` (in `core/security/scope_facade.py`) — one consult point. Fans out to every wired back-end and requires ALL of them to say yes. `add_domain`/`add_ip` propagate to every back-end that can accept them, closing the "add scope to one, other silently disagrees" gap.
- `execution_pipeline._authorize_target()` prefers the façade; falls back to the legacy `TargetScopeValidator` if nothing is wired yet.
- **#084** `AUTO_APPROVE_EXPLOITS` refused in production. In `ANTIGRAVITY_ENV=production` the env var is ignored and a WARN is logged so ops see it in log aggregation.

### Executors
- **#093** `_browser_available()` is already invoked at all four Tier-8 sites (`generic.py:5420,5480,5556,5608`). Verified as already fixed.
- **#094** `xss.py::_classify_reflection`: returns `{reflected, raw, html_encoded, js_string, attribute, textarea, json_only, likely_exploitable}` instead of a raw `payload in body` boolean. Reduces both false positives (JSON echoes, `<textarea>` echoes) and false negatives (HTML-encoded reflection inside an attribute is still risky via broken-out event handlers).
- **#096** `authentication.py::_classify_login_response`: verdict is `SUCCESS` only when the response body shows signed-in markers (`welcome`, `sign out`, `dashboard`, `my account`) OR a session cookie is set. `FAILURE` matches on ~9 rejection patterns (`invalid credentials`, `wrong password`, `access denied`, ...). Ambiguous 2xx becomes `INCONCLUSIVE` with `error_code = "LOGIN_INCONCLUSIVE"` so the retest engine picks it up instead of the pipeline flagging every wrong-password page as a bypass.

### Validation / dedup
- **#104** `dedup.process_scan`: never suppress recurring HIGH/CRITICAL findings even when severity is unchanged. Log line changes to `RECURRING_KEPT_HIGH_SEV` so consumers can distinguish this path.

### Reporting quality
- **#106** `reporting_engine.py`: `scan_id` sanitized with `re.sub(r"[^A-Za-z0-9._-]+", "_")`; strips leading `./_`; falls back to a timestamp if the sanitized value is empty. `target_dir.resolve().relative_to(self.output_dir.resolve())` boundary check ensures writes stay under the output root.
- **#107** `retest_engine.py`: `BASELINE_FILE` and `REGRESSION_REPORT_FILE` now anchored to `<repo>/data/retest/` (or `$RETEST_ARTIFACT_DIR` override). No more CWD-dependent baselines.
- **#108** `reporting.py::_poc_reproduction_table`: `curl` command built with `shlex.quote()` on URL and payload. A payload that contains `; rm -rf ~` no longer executes when the operator pastes the command.
- **#109** `report_builder.py`: CDN `<script>`/`<link>` tags carry `crossorigin`, `referrerpolicy`, and `defer`. `<noscript>` banner warns viewers when JS is blocked or the CDN is unreachable so raw data is still readable.
- **#110** `report_builder.export_pdf`: on ReportLab failure the HTML fallback is written to `<name>.html`, not `<name>.pdf`. No more `application/pdf` content-type mismatch.
- **#111** `finding_ingestion.py`: duplicate `"hidden"` dict key removed. Hidden-endpoint findings no longer silently downgrade HIGH→MEDIUM.

### OSINT
- **#085** `CensysClient.search_hosts`/`search_certificates`/`get_host`: missing PAT now returns `{"result": {"hits": [], "total": 0}, "code": "unconfigured"}` instead of raising `ValueError`. `_get_headers()` still raises, but is only reached when a token is present.
- **#086** New `core/intelligence/_provider_gate.py`: per-provider `ProviderGate` with rate limiter (defaults per-provider: Censys 1/s, Shodan 1/s, VirusTotal 0.5/s, NVD 0.5/s, etc.) and circuit breaker (3 consecutive failures → 60s cooldown). Censys is wired as the reference integration. Other providers can adopt with two lines each.

### Frontend polling races (#087)
Every polling loop across the 8 files now uses `createPoller`:
  - `AbortController` cancels an in-flight fetch when the effect unmounts or a new tick starts before the previous one finishes.
  - Monotonic generation counter guarantees a delayed response from an older tick cannot overwrite state from a newer tick.
  - `LiveScan` now uses `createPoller` for BOTH the top-level job list AND the per-scan REST fallback that runs alongside the WebSocket — closes the WS-vs-REST race that previously overwrote fresh WS payloads with stale REST responses.

## New env vars

| Var | Purpose | Default |
|---|---|---|
| `RETEST_ARTIFACT_DIR` | Where retest baseline / regression files live | `<repo>/data/retest` |
| `OSINT_RATE_<PROVIDER>` | Requests/sec cap per provider | see `_provider_gate.py` |
| `OSINT_COOLDOWN_<PROVIDER>` | Circuit-breaker cooldown seconds | 60 |
| `FP_MODEL_MIN_ROWS` | (already existed) | 200 |

## Verification

```bash
cd C:/Users/durga/Desktop/Projects/outputs
python -m py_compile \
  core/database/pg_store.py \
  core/security/scope_facade.py core/security/consent.py \
  core/execution/execution_pipeline.py \
  core/orchestration/central_brain.py \
  core/orchestration/central_brain_mixins/finding_ingestion.py \
  core/execution/executors/xss.py core/execution/executors/authentication.py \
  core/validation/dedup.py \
  core/reporting/reporting_engine.py core/reporting/retest_engine.py \
  core/reporting/reporting.py core/reporting/report_builder.py \
  core/intelligence/censys_client.py core/intelligence/_provider_gate.py \
  ui/api/server.py
# → all clean

cd ui/web && ./node_modules/.bin/vite build
# → ✓ 45 modules transformed. built in 2.03s
```

## Cumulative status

- CRITICAL (26): **26/26 closed** ✓
- HIGH (34): **34/34 addressed** ✓
- MEDIUM (34): **34/34 addressed** ✓
- LOW (46): pending
- INFO (16): pending

## What's left, briefly

- LOW items (#114–#158): bare `except:` sweeps, debug `print()` in tool_executor.py, hardcoded API URL string in Settings.jsx (already fixed cosmetically), audit-log rotation config, hash-embedding fallback purity guard, O(n²) attack-surface dedupe, etc.
- INFO items (#159–#174): observability wiring (Prometheus, tracing, structured logging), monolith splits, session cleanup on shutdown, backup/DR runbooks, CI SBOM, test coverage.

The system is now in the state described by the Deployment Checklist in `SYSTEM_DOCUMENTATION.md §12` for the "Pre-flight" and "Runtime" columns, minus LOW/INFO polish. External platform pentest + threat-model sign-off + optional SOC 2 / ISO 27001 mapping are the remaining pre-production gates.
