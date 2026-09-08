# `core/execution/executors/generic.py` split plan (#160)

`generic.py` is 5,551 lines with 85 executor classes. It grew organically
tier-by-tier. This file documents the split plan so future contributors can
migrate one tier at a time without introducing regressions.

## Current structure

Every class in `generic.py` extends `GenericHTTPExecutor` (base class at
lines 59-208). Tiers are already annotated with `# TIER N` banner comments.

## Proposed new layout

```
core/execution/executors/
├── base.py                       (already exists; ExecutorBase + interface)
├── auth_registry.py              (already exists; keep)
├── generic_base.py               <- extract GenericHTTPExecutor from generic.py
├── tiers/
│   ├── __init__.py               <- register_all() attaches every executor
│   ├── tier1_injection.py        <- SQLi, XSS, SSTI, CMDi, XXE, LDAP
│   ├── tier2_auth.py             <- JWT, OAuth, MFA, captcha, session
│   ├── tier3_apis.py             <- REST, GraphQL, gRPC, WebSocket
│   ├── tier4_cloud.py            <- AWS/Azure/GCP/K8s credentialed enumerators
│   ├── tier5_supply_chain.py     <- SCA, CI/CD secret extract
│   ├── tier6_media.py            <- stego, video, subtitle, nested archive
│   ├── tier7_smuggling.py        <- HTTP smuggling, deser, cache poisoning
│   └── tier8_browser.py          <- Live DOM XSS, clickjacking, CSP bypass
├── helpers/
│   ├── llm_budget.py             <- extract _LLMBudget
│   ├── async_bridge.py           <- extract _run_async
│   └── kali_bridge.py            <- extract _run_in_kali + _browser_available
```

Every executor's `__init__` already accepts the same `(timeout_seconds)` from
the base class, so the split is a mechanical file move + `import` rewrite.
Registration goes into `tiers/__init__.py::register_all()`.

## Sequencing

1. Extract `helpers/` first (no dependencies on any executor).
2. Extract `generic_base.py` (only depends on helpers).
3. Move one tier at a time; run the smoke test in `tests/test_new_module_imports.py`
   after each move so import paths stay valid.
4. Once every tier is out of `generic.py`, delete the file and update the
   `core.execution.executors.__init__` re-exports.
