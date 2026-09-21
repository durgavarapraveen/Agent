# Architecture Improvement — Progress (2026-09-19)

Baseline: 1736 tests, ruff clean (after F821 fix). App live throughout.

1. [~] Split god-files — DONE (bounded): settings endpoints extracted to
   ui/api/routers/settings.py via APIRouter + app.include_router; server imports
   clean (130 routes). Pattern established. STAGED: analyze/scans routers and
   central_brain.py (8.6k) split need server offline + full test run — do next.
2. [x] Persist ephemeral job state — AnalysisJobRepo (analysis_jobs table),
   write-through per step + on finish, progress endpoint falls back to DB after
   restart (fixes greybox 404-on-restart). DB roundtrip verified.
3. [x] DB migrations — _run_migrations() + schema_migrations table; ordered
   idempotent _MIGRATIONS list (seeded agent_reasoning cols + analysis_jobs).
   Verified applied + idempotent.
4. [x] Planner/normalizer contract — tests/test_normalizer_contract.py, 21 cases
   covering every shape fixed this session. All pass.
5. [x] De-duplicate UI — shared <SastTable> replaces 3 inline SAST tables in
   Analyze.jsx (asText/relPath/TaintLine already shared). Balanced.
6. [x] Config centralization — core/common/settings.py typed facade (env→.env
   precedence); wired greybox timeout + semgrep rulesets to it. Verified.
7. [x] Guardrails — baseline captured; fixed F821; ruff clean; contract tests green.

## Restart needed
server.py + backend modules changed → restart API; frontend HMR for Analyze.jsx.

## Next (staged, higher-risk)
- Extract analyze + scans routers from server.py (repeat the settings pattern).
- Split central_brain.py phase handlers into the existing mixins.
- Migrate legacy os.getenv call sites to settings facade incrementally.
