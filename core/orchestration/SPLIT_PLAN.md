# `core/orchestration/central_brain.py` split plan (#161)

`central_brain.py` is 6,707 lines. It contains the phase state machine,
planner glue, deterministic fallback catalog, and dozens of specialised
`_escalate_*` methods. The mixin extraction pattern in
`core/orchestration/central_brain_mixins/` is the right one — keep going.

## Already extracted

- `central_brain_mixins/finding_ingestion.py`  ← parse tool stdout → vulns
- `central_brain_mixins/persistence.py`         ← Postgres writers
- `central_brain_mixins/osint_bridge.py`        ← OSINT → credential shaping
- `central_brain_mixins/recon_context.py`       ← unified recon snapshot

## Proposed next extractions (one per PR)

| Extract into | What goes in it |
|---|---|
| `central_brain_mixins/fallback_catalog.py` | `_deterministic_fallback`, per-phase task catalogs (~800 lines) |
| `central_brain_mixins/phase_state.py` | `run_phase`, `_run_phase_agentic/approach_a/approach_b/legacy` (~1200 lines) |
| `central_brain_mixins/escalation.py` | `_escalate_sqli_to_dump`, `_escalate_*` (~600 lines) |
| `central_brain_mixins/agent_exploitation.py` | `_run_agent_exploitation`, `_synthesize_and_detonate_exploits` (~900 lines) |
| `central_brain_mixins/reporting_bridge.py` | Report/quality-gate handoff and postscan callbacks |
| `central_brain.py` (residual) | Constructor, phase iteration, entry points — target < 800 lines |

Every mixin follows the pattern already established: no `__init__`, methods
starting with `_`, expects `self.ctx / self.scope / self.execution_config`
to be provided by the concrete `CentralBrain`.
