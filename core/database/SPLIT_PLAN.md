# `core/database/pg_store.py` split plan (#162)

`pg_store.py` is 96 KB / ~2,500 lines with 30+ repository classes. The right
split is by DOMAIN, not by class, so every dependent import path stays local.

## Proposed layout

```
core/database/
├── schema.py                     <- _init_schema() (already the largest single-purpose block)
├── connection.py                 <- re-export of DatabaseManager
├── repos/
│   ├── __init__.py
│   ├── targets.py                <- TargetRepo
│   ├── scans.py                  <- ScanRepo (incl bootstrap_recover)
│   ├── findings.py               <- VulnRepo, FindingV2Repo
│   ├── live.py                   <- LiveDataRepo (per-scan progress/results)
│   ├── artifacts.py              <- ScanArtifactRepo
│   ├── dedup.py                  <- DedupRepo, findings_dedup helpers
│   ├── audit.py                  <- AuditRepo, ExecutionAuditRepo
│   ├── auth_bypasses.py          <- AuthBypassRepo, _encrypt_secret_field helpers
│   ├── schedules.py              <- ScheduleRepo, CampaignRepo
│   ├── attack_chains.py          <- AttackChainRepo, PostExploitRepo
│   ├── exploits.py               <- ExploitResultRepo
│   ├── tool_outputs.py           <- ToolOutputRepo, ToolExecutionRepo, CapturedRequestRepo
│   ├── agents.py                 <- LiveAgentRepo, AgentReasoningRepo, ActivityLogRepo
│   ├── memory.py                 <- ScanLLMMemoryRepo, TargetIntelRepo, RecondataRepo
│   ├── learned.py                <- LearnedSkillsRepo, AuthoredToolsRepo
│   └── metadata.py               <- ScanMetadataRepo
```

Every repo file is standalone — imports `DatabaseManager` and `psycopg2.extras`,
nothing else from `pg_store.py`. `core/database/__init__.py` re-exports every
repo so existing `from core.database.pg_store import VulnRepo` calls continue
to work during the migration.

## Sequencing

1. Move `_init_schema` and the DDL constants into `schema.py` first (no repo
   dependencies).
2. Extract the repos with the fewest cross-references (`ScheduleRepo`,
   `CampaignRepo`) as a warm-up.
3. Extract the hot-path ones (`VulnRepo`, `ScanRepo`) last so the intermediate
   commits keep every callsite working.
4. Delete `pg_store.py` once every repo is out and the re-export shim points
   to the new files.
