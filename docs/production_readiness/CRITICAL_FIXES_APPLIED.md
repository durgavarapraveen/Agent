# CRITICAL FIXES APPLIED — 2026-09-06

All **26 CRITICAL** issues from `ALL_ISSUES.md` are now closed. 16 files changed. Every file compiles clean (`python -m py_compile`).

## Files changed

| # | File | Bytes changed | Purpose |
|---|---|---|---|
| 1 | `core/memory/database.py` | ~35 lines | Rollback on exception + on happy-path; drop broken conns from pool |
| 2 | `core/memory/experience_store.py` | full rewrite | Postgres via pooled ctx-mgr, `%s` placeholders, `ON CONFLICT DO UPDATE` |
| 3 | `core/memory/failure_store.py` | full rewrite | Same pattern |
| 4 | `core/memory/strategy_store.py` | full rewrite | Same pattern |
| 5 | `core/orchestration/central_brain_mixins/persistence.py` | 1 line | `from datetime import datetime` |
| 6 | `core/validation/dedup.py` | ~40 lines | `target` column + scoped `mark_resolved`; refuses global sweep without target |
| 7 | `core/database/pg_store.py` | ~70 lines | `live_progress/live_results` re-keyed on `scan_id` + additive migration; `AuthBypassRepo` encrypts `password`/`token` |
| 8 | `core/security/encryption.py` | ~55 lines | Hardcoded fallback removed; `EncryptionKeyMissingError` on unset; explicit dev-only opt-in |
| 9 | `core/reporting/reporting.py` | ~30 lines | XOR replaced with AES-256-GCM (project encryption helper) |
| 10 | `core/intelligence/threat_intel.py` | ~10 lines | TLS verification restored by default; explicit opt-out env var |
| 11 | `core/execution/execution_pipeline.py` | ~65 lines | `_authorize_target()` gate before every executor + subclass `validate_target` composition |
| 12 | `core/tools/tool_registry.py` | ~90 lines | `HeadlessBrowserTool` scripts static; args passed as base64 JSON argv |
| 13 | `core/discovery/api_schema_importer.py` | ~15 lines | `shlex.quote` on URL / data / header |
| 14 | `core/discovery/js_analyzer.py` | ~10 lines | `shlex.quote` on URL / JS URL |
| 15 | `core/tools/tool_router.py` | ~70 lines | Strict target validation + `shlex.quote` for 24 tools; duplicate `nikto` branch removed |
| 16 | `ui/api/server.py` | ~90 lines | Production-mode auth+CORS; API key required (dev auto-gen); WS auth via subprotocol; evidence path traversal fix; RAG allowlist; SPA fallback boundary |

## Fixes by issue ID (from `ALL_ISSUES.md`)

### Authentication & authorization
- **#001** API auth off by default → require `API_KEY` in production; auto-generate dev key at `.antigravity/dev_api_key` in dev mode. `ANTIGRAVITY_ENV=production` gates behavior.
- **#002** CORS `*` → refused in production; explicit `CORS_ORIGINS` allowlist required. Dev defaults to localhost origins only.
- **#003** WS bypass → WebSocket handshake now checks the API key via `Sec-WebSocket-Protocol: api-key,<key>` subprotocol or `X-API-Key` header. Uses `hmac.compare_digest` (constant-time). Rejects with code 4401 on failure.
- **#004–#007** `validate_target()` dead code → wired into `ExecutionPipelineV2._authorize_target()`, called before every executor via `_execute()`. Uses `TargetScopeValidator.get()`; fail-closed on any error. Subclass `validate_target()` is also invoked (composition).

### Data protection / crypto
- **#008** Hardcoded encryption fallback → constant removed; `get_encryption_key()` raises `EncryptionKeyMissingError` unless in dev mode with `ENCRYPTION_KEY_DEV_UNSAFE=1` (auto-generates a random per-machine dev key at `.antigravity/dev_encryption_key`).
- **#009** XOR "encryption" → replaced with AES-256-GCM via `core.security.encryption.encrypt/decrypt`. Reader silently skips undecryptable legacy rows.
- **#010/#011** Plaintext passwords/tokens → added `_encrypt_secret_field()` / `_decrypt_secret_field()` helpers (AES-256-GCM + base64). `AuthBypassRepo.insert()` encrypts on write. `AuthBypassRepo.get_by_scan()` returns `[REDACTED]` by default; explicit `reveal_secrets=True` for server-side use only.
- **#012** TLS globally disabled for threat intel → replaced with `ssl.create_default_context()`. Opt-out via `THREAT_INTEL_INSECURE_TLS=1` env var (logs a warning).

### Persistence / data integrity
- **#013** Pool poisoning → `get_connection()` now rolls back on exception AND on happy-path exit (best-effort). Broken connections are dropped from the pool via `putconn(close=True)` so the pool refills instead of accumulating aborted conns.
- **#014** Cross-target `mark_resolved` → added `target` column to `findings_history` (additive migration via `ALTER TABLE ADD COLUMN IF NOT EXISTS`); `mark_resolved(scan_id, target)` scoped by target; refuses to run without an explicit target (logs warning). `process_scan` infers target from findings if not passed.
- **#015** `live_progress/live_results` singleton → schema migrated: dropped `id INT PRIMARY KEY DEFAULT 1`, made `scan_id` the primary key. Additive `DO $mig$` block handles pre-fix DBs. `upsert_progress/results` now `ON CONFLICT (scan_id)`. `get_progress/results` accepts `scan_id` param; falls to most-recently-updated for backward compat.
- **#016** `persistence.py` NameError → `from datetime import datetime` added at module top.
- **#017/#018/#019** Broken memory stores → all three rewritten to use `DatabaseManager.get_connection()` context manager, `%s` placeholders, `ON CONFLICT DO UPDATE`, and `RealDictCursor` for reads. Instantiation no longer requires a `MemoryDatabase` arg.

### Path / file safety
- **#020** `/api/evidence/{filename}` path traversal → filename now goes through strict allowlist regex `[A-Za-z0-9._-]+`, no path separators, no `.`/`..`; result is `Path.resolve()`'d and checked with `relative_to(evidence_dir)`.
- **#021** `/api/rag/ingest/file` arbitrary-read → target file must live under one of `RAG_INGEST_ROOTS` (env, `;`-separated); defaults to `data/rag_ingest` under the repo. Uploads still go through `/api/rag/ingest/uploaded`.
- **#022** SPA fallback traversal → resolve `full_path` inside `_FRONTEND_DIR.resolve()`; anything that escapes falls back to `index.html`.

### Injection surfaces
- **#023** `HeadlessBrowserTool` code injection → user-controlled URL/JS/form-data are now passed as a **base64-encoded JSON argv token** to a **static Python driver source constant**. Because the alphabet is `[A-Za-z0-9+/=]`, breaking out of the source-string is impossible. The five old `_script_*` methods that concatenated raw input have been removed.
- **#024** `api_schema_importer.py` shell injection → all four call sites now use `shlex.quote()` on URL / data / header before command construction.
- **#025** `js_analyzer.py` shell injection → three call sites (fetch, linkfinder, secretfinder) now use `shlex.quote()` on the JS URL.
- **#026** `tool_router.py` shell injection → target must pass strict URL/hostname regex validation; then `shlex.quote()` on every substituted `target`/`domain`/`base_domain`. Invalid targets return a `TOOL_UNAVAILABLE` error tagged `Target failed validation (potential injection)`. Duplicate `nikto` branch (dead code) removed.

## New environment variables (all optional; all documented in code)

| Var | Purpose | Default |
|---|---|---|
| `ANTIGRAVITY_ENV` | `development` (dev-friendly) or `production` (strict boot gates) | `development` |
| `API_KEY` | HTTP + WS auth secret | required in prod; auto-gen in dev |
| `CORS_ORIGINS` | Explicit CORS allowlist | required in prod; localhost list in dev |
| `ENCRYPTION_KEY` | AES-256-GCM master (base64 or raw 32 bytes) | required unless dev-unsafe |
| `ENCRYPTION_KEY_DEV_UNSAFE` | `1` to auto-generate dev key | unset |
| `THREAT_INTEL_INSECURE_TLS` | `1` to disable TLS verify on threat feeds | unset (verified) |
| `RAG_INGEST_ROOTS` | Semicolon-separated allowed ingestion roots | `data/rag_ingest` |

## What is NOT done (deliberate scope)

The 26 P0 items are closed. The following are **explicitly deferred** to phases 2-6 in `RISK_MATRIX.md`:

- Data migration to re-encrypt existing plaintext `auth_bypasses.password/token` rows. New writes are encrypted; legacy rows are transparently returned as-is by `_decrypt_secret_field()` for backward compat. Ship a one-shot migration script when rotating the DB.
- Alembic / versioned migrations. All new schema changes here are additive via `ALTER TABLE ... IF NOT EXISTS` / `DO $$ … $$` blocks so existing DBs survive.
- Frontend `api.js` header propagation (`X-API-Key`). The backend now enforces the key strictly; the SPA needs `X-API-Key: <key>` on every request and `Sec-WebSocket-Protocol: api-key,<key>` for the live socket. This is a P1 UI change and does not gate the backend fix.
- All P1/P2/P3 issues from `ALL_ISSUES.md`.

## Verification

```bash
cd C:/Users/durga/Desktop/Projects/outputs
python -m py_compile \
  core/memory/database.py core/memory/experience_store.py \
  core/memory/failure_store.py core/memory/strategy_store.py \
  core/orchestration/central_brain_mixins/persistence.py \
  core/validation/dedup.py core/database/pg_store.py \
  core/security/encryption.py core/reporting/reporting.py \
  core/intelligence/threat_intel.py \
  core/execution/execution_pipeline.py \
  core/tools/tool_registry.py \
  core/discovery/api_schema_importer.py \
  core/discovery/js_analyzer.py core/tools/tool_router.py \
  ui/api/server.py
```
All 16 files compile clean.

## Recommended next actions

1. Set `API_KEY` and `ENCRYPTION_KEY` in `.env` before restarting the API (or export them). In dev, both auto-generate.
2. Restart the API — the additive DB migrations (`ALTER TABLE ... IF NOT EXISTS`) run on boot via `_init_schema`.
3. Add `X-API-Key` header to `ui/web/src/api.js` fetch calls and WebSocket subprotocol; otherwise the UI will show blank tables (401 silently caught by `.catch(()=>{})`).
4. Run the scan workflow end-to-end against a test target to confirm: `_authorize_target` gate fires; findings persist (persistence.py fix); dedup no longer contaminates across targets; live progress is per-scan.
5. Proceed to P1 fixes per `RISK_MATRIX.md` §Week 2.
