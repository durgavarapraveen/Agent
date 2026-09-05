# Obsolete / quarantined tests

These test files reference modules that no longer exist in the codebase
(deleted or renamed during earlier refactors) OR contain no actual
`def test_*` functions (one-off scratch harnesses).

They are kept in git history in case any of the deleted implementations
need to be resurrected. Pytest does NOT collect from this directory
(the leading underscore excludes it from default discovery).

## Contents

**Import missing modules** (deleted implementations):

| File | Missing module(s) |
|------|-------------------|
| test_end_to_end_pipeline.py | `core.exploitation.credential_simulator`, `core.orchestration.llm_orchestrator` |
| test_identity.py | `core.identity.login_flow` (LoginFlowEngine) |
| test_injection.py | `core.injection.injection_executor` |
| test_intelligence.py | `core.intelligence.hypothesis_engine` (moved to `core.reasoning.hypothesis_engine`) |
| test_module1_3_web_api.py | `core.exploitation.web_advanced` (WebAdvancedTester), `core.exploitation.api_testing` |
| test_module1_4_cloud.py | `core.intelligence.cloud_scanner` (CloudInfrastructureScanner) |
| test_module1_simulator.py | `core.exploitation.credential_simulator`, `core.exploitation.persistence_auditor` |

**Scratch / no assertions** (files starting with `test_` but containing no
`def test_*` functions — presumably one-off runner scripts):

| File | Purpose (inferred) |
|------|-------------------|
| test_app.py | Local test-app fixture used by other tests |
| test_exploitation.py | Manual exploitation runner |
| test_live_intelligence.py | Manual live-intelligence check |
| test_recon_pipeline.py | Manual recon pipeline check |
| capture_test.py | Manual HTTP capture experiment |

## Restoring a test

1. `git mv tests/_obsolete/<file> tests/<file>`
2. Update imports to point at whichever module replaced the missing one
3. Re-run `pytest tests/<file>`
