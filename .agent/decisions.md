# Architecture decisions (adaptive testing pipeline)

Concise map for contributors. Full rationale: `gaps.md`.

## Core split: payloads = DATA, detection = LOGIC
- **DATA** — every payload/variant lives in the `PayloadCatalog` (RDS), auto-synced
  from PayloadsAllTheThings (+nuclei) by `PayloadUpdater`. Never hand-maintained
  in module code. New PATT payload → picked up on next sync, zero code change.
- **LOGIC** — how to confirm a class lives in one place: `core/evidence/oracle.py`
  (`OracleEngine`, one `_oracle_<class>(ev, cfg) -> OracleResult` per class).

## The one flow (gaps §0/§2/§4)
```
SurfaceClassifier (core/recon/surface_classifier.py)
   observed data → Surface{url, injection_points[], applicable_classes[]}   (name-agnostic; shape-based)
        ↓
Dispatcher (core/orchestration/dispatcher.py)
   surface × point × class  → UniversalProbeEngine.probe_point
        ↓
UniversalProbeEngine (core/payloads/probe_engine.py)
   catalog.select(class) → inject at REAL point → OracleEngine.evaluate → catalog.record_outcome
```
- Injection classes run through the engine. Depth/logic-coupled classes
  (FILE_UPLOAD, IDOR, JWT, WebSocket, GraphQL, race, business-logic) are
  DELEGATED to their dedicated probes (see `dispatcher.DELEGATED`), not duplicated.
- Wired in `central_brain.py` exploitation block: Dispatcher → UPE (fallback) →
  differential/api/business-logic → workflow.

## Business logic (gaps §1)
`core/workflow/`: Recorder (observed journey → steps + state deltas) → Learner
(state machine + invariants) → ViolationTester (value tamper / replay / step-skip).
Wired after business_logic_probe.

## Phases (gaps §3)
`ExecutionPhase.UNDERSTAND` precedes RECON; transitions in `adaptive_planner.py`.

## Adaptivity (gaps §5)
Loop: observe → KnowledgeGraph → HypothesisEngine → AdaptivePlanner → execute →
`catalog.record_outcome` feedback. LLM (novel payloads, step labels, "looks
abusable") is Bedrock-gated and dormant until model access is granted.

## Adding a new vuln category (the whole recipe)
1. **Payloads** — already in the catalog if PATT has the category. Map its PATT
   dir in `catalog._PATT_DIR_MAP` to a distinct `vuln_class`; add a
   `catalog._CLASS_FALLBACK` entry (base class to borrow payloads from until the
   bundle is rebuilt) and a `_CLASS_SEVERITY` entry.
2. **Oracle** — add `_oracle_<class>` in `oracle.py` and register the key in
   `_DEFAULT_ORACLES`.
3. **Trigger** — add the signal→class rule in `SurfaceClassifier._assign_classes`
   (and `_value_signals` if a new signal is needed).
4. **Route** — add the class to `dispatcher.ENGINE_CLASSES` (engine-injectable) or
   `dispatcher.DELEGATED` (owned by a dedicated probe), and refine
   `Dispatcher._point_supports` if it only applies to certain point kinds.
Nothing else. No new module per category.

## Auto-sync (gaps §6)
`PayloadUpdater.maybe_update()` (called on scan start, interval-guarded via
`PAYLOAD_SYNC_INTERVAL_HOURS`, default 24h) git-pulls the source dirs
(`NUCLEI_TEMPLATES_DIR`, `PAYLOADS_ALL_THE_THINGS_DIR`, `CUSTOM_PAYLOADS_DIR`) and
re-ingests. In AWS these point at an EFS/volume checkout; agent-host egress to
github is infra-allowlisted, separate from scan-target scope.

## AWS / Bedrock
RDS Postgres via `DatabaseManager` (env/Secrets Manager). LLM via Bedrock
`bedrock-runtime`, model+region from env, IAM auth; gated so deterministic paths
run when model access is not yet granted.
